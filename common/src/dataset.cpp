#include "pir/common/dataset.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <stdexcept>

namespace pir::common
{
    namespace
    {
        void validate_parameters(const DatasetParameters &parameters)
        {
            if (parameters.document_count == 0)
                throw std::invalid_argument("document_count must be positive");
            if (parameters.keyword_count == 0)
                throw std::invalid_argument("keyword_count must be positive");
            if (parameters.keywords_per_document == 0 ||
                parameters.keywords_per_document > parameters.keyword_count)
            {
                throw std::invalid_argument(
                    "keywords_per_document must be in [1, keyword_count]");
            }
            if (parameters.keyword_count >
                static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                throw std::invalid_argument("keyword_count exceeds the keyword id type");
            }
            if (parameters.document_count >
                std::numeric_limits<std::size_t>::max() /
                    parameters.keywords_per_document)
            {
                throw std::overflow_error("document edge count overflow");
            }
        }

        [[nodiscard]] bool contains_keyword(
            const Document &document,
            const std::uint32_t keyword)
        {
            return std::binary_search(
                document.keyword_ids.begin(), document.keyword_ids.end(), keyword);
        }
    }

    Dataset generate_balanced_dataset(const DatasetParameters &parameters)
    {
        validate_parameters(parameters);
        std::mt19937_64 generator(parameters.seed);
        std::vector<std::uint32_t> keyword_permutation(parameters.keyword_count);
        std::iota(keyword_permutation.begin(), keyword_permutation.end(), 0U);
        std::shuffle(keyword_permutation.begin(), keyword_permutation.end(), generator);

        Dataset dataset{parameters, {}};
        dataset.documents.reserve(parameters.document_count);
        std::size_t edge = 0;
        for (std::size_t document_index = 0;
             document_index < parameters.document_count;
             ++document_index)
        {
            Document document;
            document.id = document_index;
            document.keyword_ids.reserve(parameters.keywords_per_document);
            for (std::size_t offset = 0;
                 offset < parameters.keywords_per_document;
                 ++offset, ++edge)
            {
                document.keyword_ids.push_back(
                    keyword_permutation[edge % parameters.keyword_count]);
            }
            std::sort(document.keyword_ids.begin(), document.keyword_ids.end());
            document.payload.resize(parameters.payload_bytes);
            for (auto &byte : document.payload)
                byte = static_cast<std::uint8_t>(generator() & 0xffU);
            dataset.documents.push_back(std::move(document));
        }

        // Cycling through a seeded permutation assigns floor(E/K) or ceil(E/K) edges
        // per keyword in O(E), which is optimal because every edge must be materialized.
        return dataset;
    }

    Dataset generate_conjunction_dataset(
        const DatasetParameters &parameters,
        const std::size_t query_keyword_count,
        const std::size_t target_result_count)
    {
        validate_parameters(parameters);
        if (query_keyword_count == 0 ||
            query_keyword_count > parameters.keywords_per_document)
            throw std::invalid_argument(
                "query_keyword_count must be in [1, keywords_per_document]");
        if (query_keyword_count > parameters.keyword_count)
            throw std::invalid_argument("query_keyword_count exceeds keyword_count");
        if (target_result_count > parameters.document_count)
            throw std::invalid_argument("target_result_count exceeds document_count");

        auto dataset = generate_balanced_dataset(parameters);
        auto target_frequencies = keyword_frequencies(dataset);
        const auto original_edge_count =
            parameters.document_count * parameters.keywords_per_document;

        // For one keyword, its frequency equals the conjunction result count. For
        // multi-keyword queries, balanced frequencies are retained whenever they can
        // support the requested intersection; only infeasible points are relaxed.
        if (query_keyword_count == 1)
        {
            target_frequencies.front() = target_result_count;
        }
        else
        {
            for (std::size_t keyword = 0; keyword < query_keyword_count; ++keyword)
                target_frequencies[keyword] = std::max(
                    target_frequencies[keyword], target_result_count);
        }

        auto current_edge_count = std::accumulate(
            target_frequencies.begin(), target_frequencies.end(), std::size_t{0});
        using FrequencyEntry = std::pair<std::size_t, std::size_t>;
        if (current_edge_count > original_edge_count)
        {
            std::priority_queue<FrequencyEntry> donors;
            for (std::size_t keyword = query_keyword_count;
                 keyword < parameters.keyword_count;
                 ++keyword)
                donors.emplace(target_frequencies[keyword], keyword);
            while (current_edge_count > original_edge_count)
            {
                if (donors.empty() || donors.top().first == 0)
                    throw std::invalid_argument(
                        "target conjunction leaves no capacity for non-query keywords");
                const auto [frequency, keyword] = donors.top();
                donors.pop();
                target_frequencies[keyword] = frequency - 1;
                donors.emplace(frequency - 1, keyword);
                --current_edge_count;
            }
        }
        else if (current_edge_count < original_edge_count)
        {
            std::priority_queue<
                FrequencyEntry,
                std::vector<FrequencyEntry>,
                std::greater<>> recipients;
            for (std::size_t keyword = query_keyword_count;
                 keyword < parameters.keyword_count;
                 ++keyword)
                recipients.emplace(target_frequencies[keyword], keyword);
            while (current_edge_count < original_edge_count)
            {
                if (recipients.empty() || recipients.top().first >= parameters.document_count)
                    throw std::invalid_argument(
                        "non-query keywords cannot absorb the relaxed frequency deficit");
                const auto [frequency, keyword] = recipients.top();
                recipients.pop();
                target_frequencies[keyword] = frequency + 1;
                recipients.emplace(frequency + 1, keyword);
                ++current_edge_count;
            }
        }

        for (auto &document : dataset.documents) document.keyword_ids.clear();
        std::vector<std::size_t> remaining = target_frequencies;
        std::vector<std::size_t> open_slots(
            parameters.document_count, parameters.keywords_per_document);
        for (std::size_t document = 0; document < target_result_count; ++document)
        {
            for (std::size_t keyword = 0; keyword < query_keyword_count; ++keyword)
            {
                if (remaining[keyword] == 0)
                    throw std::invalid_argument(
                        "target conjunction exceeds a query keyword frequency");
                dataset.documents[document].keyword_ids.push_back(
                    static_cast<std::uint32_t>(keyword));
                --remaining[keyword];
                --open_slots[document];
            }
        }

        const std::size_t non_target_document_count =
            parameters.document_count - target_result_count;
        const std::size_t maximum_query_edges_per_non_target =
            std::min(parameters.keywords_per_document, query_keyword_count - 1);
        std::size_t remaining_query_edges = std::accumulate(
            remaining.begin(),
            remaining.begin() + static_cast<std::ptrdiff_t>(query_keyword_count),
            std::size_t{0});
        if (remaining_query_edges >
            non_target_document_count * maximum_query_edges_per_non_target)
            throw std::invalid_argument(
                "target conjunction query degrees exceed non-target capacity");
        for (std::size_t keyword = 0; keyword < query_keyword_count; ++keyword)
            if (remaining[keyword] > non_target_document_count)
                throw std::invalid_argument(
                    "query keyword degree exceeds distinct non-target documents");

        // A continuous cyclic assignment balances query edges within one across all
        // non-target documents. It therefore meets the q-1 cap whenever the total
        // capacity test above passes, in optimal O(number of query edges) time.
        std::size_t query_cursor = 0;
        for (std::size_t keyword = 0; keyword < query_keyword_count; ++keyword)
        {
            const std::size_t count = remaining[keyword];
            for (std::size_t offset = 0; offset < count; ++offset)
            {
                const std::size_t document = target_result_count +
                    ((query_cursor + offset) % non_target_document_count);
                dataset.documents[document].keyword_ids.push_back(
                    static_cast<std::uint32_t>(keyword));
                --open_slots[document];
            }
            if (non_target_document_count != 0)
                query_cursor = (query_cursor + count) % non_target_document_count;
            remaining[keyword] = 0;
        }

        const auto remaining_slot_count = std::accumulate(
            open_slots.begin(), open_slots.end(), std::size_t{0});
        const auto remaining_non_query_edges = std::accumulate(
            remaining.begin() + static_cast<std::ptrdiff_t>(query_keyword_count),
            remaining.end(), std::size_t{0});
        if (remaining_slot_count != remaining_non_query_edges)
            throw std::logic_error("controlled conjunction remaining edge count mismatch");

        std::vector<std::vector<std::size_t>> documents_by_degree(
            parameters.keywords_per_document + 1);
        for (std::size_t document = 0; document < open_slots.size(); ++document)
        {
            if (open_slots[document] > parameters.keyword_count - query_keyword_count)
                throw std::invalid_argument(
                    "non-query keywords cannot fill a document without duplicates");
            documents_by_degree[open_slots[document]].push_back(document);
        }
        std::vector<std::vector<std::size_t>> keywords_by_degree(
            parameters.document_count + 1);
        std::size_t maximum_keyword_degree = 0;
        for (std::size_t keyword = query_keyword_count;
             keyword < parameters.keyword_count;
             ++keyword)
        {
            if (remaining[keyword] > parameters.document_count)
                throw std::invalid_argument(
                    "non-query keyword degree exceeds document count");
            keywords_by_degree[remaining[keyword]].push_back(keyword);
            maximum_keyword_degree = std::max(
                maximum_keyword_degree, remaining[keyword]);
        }

        // Bipartite Havel-Hakimi connects each largest document demand to the
        // currently largest keyword degrees. Degree buckets make every edge move
        // O(1), so total construction is O(E+M+K), optimal for materializing E edges.
        for (std::size_t document_degree = parameters.keywords_per_document;
             document_degree != 0;
             --document_degree)
        {
            auto &documents = documents_by_degree[document_degree];
            while (!documents.empty())
            {
                const std::size_t document = documents.back();
                documents.pop_back();
                std::vector<std::pair<std::size_t, std::size_t>> selected;
                selected.reserve(document_degree);
                for (std::size_t edge = 0; edge < document_degree; ++edge)
                {
                    while (maximum_keyword_degree != 0 &&
                           keywords_by_degree[maximum_keyword_degree].empty())
                        --maximum_keyword_degree;
                    if (maximum_keyword_degree == 0)
                        throw std::runtime_error(
                            "controlled conjunction non-query degrees are not graphical");
                    const std::size_t keyword =
                        keywords_by_degree[maximum_keyword_degree].back();
                    keywords_by_degree[maximum_keyword_degree].pop_back();
                    selected.emplace_back(keyword, maximum_keyword_degree);
                    dataset.documents[document].keyword_ids.push_back(
                        static_cast<std::uint32_t>(keyword));
                }
                for (const auto &[keyword, old_degree] : selected)
                {
                    remaining[keyword] = old_degree - 1;
                    keywords_by_degree[old_degree - 1].push_back(keyword);
                    maximum_keyword_degree = std::max(
                        maximum_keyword_degree, old_degree - 1);
                }
                open_slots[document] = 0;
            }
        }
        if (std::any_of(
                remaining.begin(), remaining.end(),
                [](const std::size_t count) { return count != 0; }))
            throw std::logic_error("controlled conjunction left unmatched keyword degrees");

        for (auto &document : dataset.documents)
        {
            if (document.keyword_ids.size() != parameters.keywords_per_document)
                throw std::logic_error("controlled dataset document degree mismatch");
            std::sort(document.keyword_ids.begin(), document.keyword_ids.end());
        }
        if (keyword_frequencies(dataset) != target_frequencies)
            throw std::logic_error("controlled dataset keyword degree mismatch");
        std::size_t actual_result_count = 0;
        for (const auto &document : dataset.documents)
        {
            bool match = true;
            for (std::size_t keyword = 0; keyword < query_keyword_count; ++keyword)
                match = match && std::binary_search(
                    document.keyword_ids.begin(), document.keyword_ids.end(),
                    static_cast<std::uint32_t>(keyword));
            actual_result_count += static_cast<std::size_t>(match);
        }
        if (actual_result_count != target_result_count)
            throw std::logic_error("controlled dataset result count mismatch");
        return dataset;
    }

    std::vector<std::size_t> keyword_frequencies(const Dataset &dataset)
    {
        std::vector<std::size_t> frequencies(dataset.parameters.keyword_count, 0);
        for (const auto &document : dataset.documents)
        {
            for (const auto keyword : document.keyword_ids)
            {
                if (keyword >= frequencies.size())
                    throw std::out_of_range("document keyword is outside keyword_count");
                ++frequencies[keyword];
            }
        }
        return frequencies;
    }

    std::size_t apply_degree_preserving_edge_swaps(
        Dataset &dataset,
        const std::size_t requested_swaps,
        const std::uint64_t seed)
    {
        if (requested_swaps == 0) return 0;
        if (dataset.documents.size() < 2)
            throw std::invalid_argument("edge swaps require at least two documents");
        for (const auto &document : dataset.documents)
        {
            if (document.keyword_ids.empty())
                throw std::invalid_argument("edge swaps require nonempty document keywords");
        }

        std::mt19937_64 generator(seed);
        std::uniform_int_distribution<std::size_t> document_distribution(
            0, dataset.documents.size() - 1);
        const std::size_t maximum_attempts = requested_swaps * 1024 + 1024;
        std::size_t completed = 0;
        for (std::size_t attempt = 0;
             attempt < maximum_attempts && completed < requested_swaps;
             ++attempt)
        {
            const std::size_t first_index = document_distribution(generator);
            const std::size_t second_index = document_distribution(generator);
            if (first_index == second_index) continue;
            auto &first = dataset.documents[first_index];
            auto &second = dataset.documents[second_index];
            std::uniform_int_distribution<std::size_t> first_edge(
                0, first.keyword_ids.size() - 1);
            std::uniform_int_distribution<std::size_t> second_edge(
                0, second.keyword_ids.size() - 1);
            const std::size_t first_position = first_edge(generator);
            const std::size_t second_position = second_edge(generator);
            const auto first_keyword = first.keyword_ids[first_position];
            const auto second_keyword = second.keyword_ids[second_position];
            if (first_keyword == second_keyword ||
                contains_keyword(first, second_keyword) ||
                contains_keyword(second, first_keyword))
            {
                continue;
            }
            first.keyword_ids[first_position] = second_keyword;
            second.keyword_ids[second_position] = first_keyword;
            std::sort(first.keyword_ids.begin(), first.keyword_ids.end());
            std::sort(second.keyword_ids.begin(), second.keyword_ids.end());
            ++completed;
        }
        if (completed != requested_swaps)
            throw std::runtime_error("unable to complete requested degree-preserving edge swaps");
        return completed;
    }
}
