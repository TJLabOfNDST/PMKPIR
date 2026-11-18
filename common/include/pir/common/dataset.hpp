#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pir::common
{
    struct DatasetParameters
    {
        std::size_t document_count = 1024;
        std::size_t keyword_count = 64;
        std::size_t keywords_per_document = 4;
        std::size_t payload_bytes = 64;
        std::uint64_t seed = 20261027;

        bool operator==(const DatasetParameters &) const = default;
    };

    struct Document
    {
        std::size_t id = 0;
        std::vector<std::uint32_t> keyword_ids;
        std::vector<std::uint8_t> payload;

        bool operator==(const Document &) const = default;
    };

    struct Dataset
    {
        DatasetParameters parameters;
        std::vector<Document> documents;

        bool operator==(const Dataset &) const = default;
    };

    [[nodiscard]] Dataset generate_balanced_dataset(
        const DatasetParameters &parameters);

    [[nodiscard]] Dataset generate_conjunction_dataset(
        const DatasetParameters &parameters,
        std::size_t query_keyword_count,
        std::size_t target_result_count);

    [[nodiscard]] std::vector<std::size_t> keyword_frequencies(
        const Dataset &dataset);

    [[nodiscard]] std::size_t apply_degree_preserving_edge_swaps(
        Dataset &dataset,
        std::size_t requested_swaps,
        std::uint64_t seed);
}
