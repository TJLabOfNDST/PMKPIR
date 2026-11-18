#pragma once

#include "pir/common/boolean_query.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace pir::pmkpir
{
    struct Literal
    {
        std::size_t source_index = 0;
        bool negated = false;
    };

    enum class PlanKind
    {
        literal,
        local_dnf,
        logical_and,
        logical_or
    };

    struct PlanNode
    {
        PlanKind kind = PlanKind::literal;
        Literal literal;
        std::vector<std::vector<Literal>> dnf_clauses;
        std::size_t padded_clause_length = 1;
        std::size_t padded_clause_count = 1;
        std::vector<std::shared_ptr<const PlanNode>> children;
    };

    struct CompiledQuery
    {
        std::size_t block_count = 0;
        std::size_t leaf_count = 0;
        // The distinct queried keywords, in first-occurrence order. Each keyword is
        // packed into exactly one logical sub-block, so a query ciphertext multiplexes
        // B distinct keywords and repeated keyword leaves share the same source slot.
        std::vector<std::uint32_t> packed_keywords;
        std::shared_ptr<const PlanNode> root;
        bool uses_fallback = false;
    };

    [[nodiscard]] CompiledQuery compile_query(
        const pir::common::BooleanQuery &query,
        std::size_t block_count);
}
