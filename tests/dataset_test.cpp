#include "pir/common/dataset.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <set>
#include <stdexcept>
#include <vector>

namespace
{
    void require(const bool condition, const char *message)
    {
        if (!condition) throw std::runtime_error(message);
    }
}

int main()
{
    try
    {
        const pir::common::DatasetParameters parameters{
            .document_count = 16,
            .keyword_count = 8,
            .keywords_per_document = 3,
            .payload_bytes = 8,
            .seed = 20261027};
        const auto first = pir::common::generate_balanced_dataset(parameters);
        const auto second = pir::common::generate_balanced_dataset(parameters);
        require(first == second, "same seed must reproduce the exact dataset");
        require(first.documents.size() == 16, "document count differs");

        for (std::size_t index = 0; index < first.documents.size(); ++index)
        {
            const auto &document = first.documents[index];
            require(document.id == index, "document ids must be stable positions");
            require(document.keyword_ids.size() == 3, "document degree differs");
            require(document.payload.size() == 8, "payload width differs");
            const std::set<std::uint32_t> unique(
                document.keyword_ids.begin(), document.keyword_ids.end());
            require(unique.size() == 3, "document keywords must be distinct");
        }

        const auto frequencies = pir::common::keyword_frequencies(first);
        const auto [minimum, maximum] = std::minmax_element(
            frequencies.begin(), frequencies.end());
        require(*maximum - *minimum <= 1, "keyword frequencies must be balanced");

        auto rewired = first;
        const auto swaps = pir::common::apply_degree_preserving_edge_swaps(
            rewired, 12, 20261027);
        require(swaps == 12, "all requested valid edge swaps must complete");
        require(rewired != first, "edge swaps must change the incidence relation");
        require(
            pir::common::keyword_frequencies(rewired) == frequencies,
            "edge swaps must preserve keyword degrees");
        for (const auto &document : rewired.documents)
        {
            require(document.keyword_ids.size() == 3, "edge swaps changed document degree");
            const std::set<std::uint32_t> unique(
                document.keyword_ids.begin(), document.keyword_ids.end());
            require(unique.size() == 3, "edge swaps introduced a duplicate edge");
        }

        bool rejected = false;
        try
        {
            (void)pir::common::generate_balanced_dataset({4, 2, 3, 1, 1});
        }
        catch (const std::invalid_argument &)
        {
            rejected = true;
        }
        require(rejected, "keywords_per_document > keyword_count must be rejected");

        const auto controlled = pir::common::generate_conjunction_dataset(
            {1024, 64, 4, 64, 20261027}, 4, 8);
        const auto controlled_again = pir::common::generate_conjunction_dataset(
            {1024, 64, 4, 64, 20261027}, 4, 8);
        require(controlled == controlled_again, "controlled dataset must be deterministic");
        const std::array<std::uint32_t, 4> conjunction_keywords{0, 1, 2, 3};
        std::size_t controlled_matches = 0;
        for (const auto &document : controlled.documents)
            controlled_matches += static_cast<std::size_t>(
                std::includes(
                    document.keyword_ids.begin(), document.keyword_ids.end(),
                    conjunction_keywords.begin(), conjunction_keywords.end()));
        require(controlled_matches == 8, "controlled balanced dataset target differs");
        const auto controlled_frequencies = pir::common::keyword_frequencies(controlled);
        const auto [controlled_min, controlled_max] = std::minmax_element(
            controlled_frequencies.begin(), controlled_frequencies.end());
        require(*controlled_max - *controlled_min <= 1,
                "feasible controlled dataset must remain frequency-balanced");

        const auto dense_two_keyword = pir::common::generate_conjunction_dataset(
            {1024, 64, 32, 64, 20261027}, 2, 8);
        const std::array<std::uint32_t, 2> two_keywords{0, 1};
        std::size_t dense_two_keyword_matches = 0;
        for (const auto &document : dense_two_keyword.documents)
            dense_two_keyword_matches += static_cast<std::size_t>(
                std::includes(
                    document.keyword_ids.begin(), document.keyword_ids.end(),
                    two_keywords.begin(), two_keywords.end()));
        require(dense_two_keyword_matches == 8,
                "experiment 3 z=2 target result count differs");
        const auto dense_two_keyword_frequencies =
            pir::common::keyword_frequencies(dense_two_keyword);
        const auto [dense_minimum, dense_maximum] = std::minmax_element(
            dense_two_keyword_frequencies.begin(),
            dense_two_keyword_frequencies.end());
        require(*dense_maximum - *dense_minimum <= 1,
                "experiment 3 z=2 must preserve balanced keyword frequencies");

        const auto relaxed = pir::common::generate_conjunction_dataset(
            {4096, 64, 4, 64, 20261027}, 4, 1024);
        std::size_t relaxed_matches = 0;
        for (const auto &document : relaxed.documents)
            relaxed_matches += static_cast<std::size_t>(
                std::includes(
                    document.keyword_ids.begin(), document.keyword_ids.end(),
                    conjunction_keywords.begin(), conjunction_keywords.end()));
        require(relaxed_matches == 1024, "experiment 11 relaxed target differs");
        const auto relaxed_frequencies = pir::common::keyword_frequencies(relaxed);
        require(std::all_of(
                    relaxed_frequencies.begin(), relaxed_frequencies.begin() + 4,
                    [](const auto frequency) { return frequency >= 1024; }),
                "experiment 11 query frequencies were not relaxed");

        std::cout << "dataset_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "dataset_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
