#include "pir/pmkpir/query_compiler.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace pir::pmkpir
{
    namespace
    {
        struct NnfNode
        {
            PlanKind kind = PlanKind::literal;
            std::size_t leaf_position = 0;
            bool negated = false;
            std::shared_ptr<const NnfNode> left;
            std::shared_ptr<const NnfNode> right;
        };

        using Dnf = std::vector<std::vector<Literal>>;
        using DnfAttempt = std::optional<Dnf>;
        using DnfCache = std::unordered_map<const NnfNode *, DnfAttempt>;

        [[nodiscard]] bool is_power_of_two(const std::size_t value) noexcept
        {
            return value != 0 && (value & (value - 1)) == 0;
        }

        [[nodiscard]] std::size_t next_power_of_two(const std::size_t value)
        {
            if (value == 0) throw std::invalid_argument("DNF dimension must be positive");
            std::size_t result = 1;
            while (result < value)
            {
                if (result > std::numeric_limits<std::size_t>::max() / 2)
                    throw std::overflow_error("DNF dimension overflow");
                result <<= 1U;
            }
            return result;
        }

        [[nodiscard]] bool fits_shape(
            const std::size_t maximum_clause_length,
            const std::size_t clause_count,
            const std::size_t block_count)
        {
            if (maximum_clause_length == 0 || clause_count == 0) return false;
            const auto padded_length = next_power_of_two(maximum_clause_length);
            const auto padded_count = next_power_of_two(clause_count);
            return padded_length <= block_count &&
                   padded_count <= block_count / padded_length;
        }

        [[nodiscard]] std::shared_ptr<const NnfNode> normalize(
            const pir::common::BooleanQuery &query,
            const bool negated,
            std::vector<std::uint32_t> &leaves)
        {
            using Query = pir::common::BooleanQuery;
            if (query.kind() == Query::Kind::keyword)
            {
                auto node = std::make_shared<NnfNode>();
                node->leaf_position = leaves.size();
                node->negated = negated;
                leaves.push_back(query.keyword_id());
                return node;
            }
            if (query.kind() == Query::Kind::logical_not)
                return normalize(query.left(), !negated, leaves);
            auto node = std::make_shared<NnfNode>();
            const bool source_is_and = query.kind() == Query::Kind::logical_and;
            const bool output_is_and = negated ? !source_is_and : source_is_and;
            node->kind = output_is_and ? PlanKind::logical_and : PlanKind::logical_or;
            node->left = normalize(query.left(), negated, leaves);
            node->right = normalize(query.right(), negated, leaves);
            return node;
        }

        [[nodiscard]] std::size_t maximum_clause_length(const Dnf &dnf)
        {
            std::size_t maximum = 0;
            for (const auto &clause : dnf) maximum = std::max(maximum, clause.size());
            return maximum;
        }

        DnfAttempt &bounded_dnf(
            const std::shared_ptr<const NnfNode> &node,
            const std::vector<std::size_t> &leaf_sources,
            const std::size_t block_count,
            DnfCache &cache)
        {
            if (const auto found = cache.find(node.get()); found != cache.end())
                return found->second;
            if (node->kind == PlanKind::literal)
            {
                Dnf value{{Literal{leaf_sources.at(node->leaf_position), node->negated}}};
                return cache.emplace(node.get(), std::move(value)).first->second;
            }
            const auto &left = bounded_dnf(node->left, leaf_sources, block_count, cache);
            const auto &right = bounded_dnf(node->right, leaf_sources, block_count, cache);
            if (!left || !right)
                return cache.emplace(node.get(), std::nullopt).first->second;
            const auto left_maximum = maximum_clause_length(*left);
            const auto right_maximum = maximum_clause_length(*right);
            Dnf value;
            if (node->kind == PlanKind::logical_or)
            {
                if (left->size() > std::numeric_limits<std::size_t>::max() - right->size())
                    return cache.emplace(node.get(), std::nullopt).first->second;
                const auto count = left->size() + right->size();
                if (!fits_shape(std::max(left_maximum, right_maximum), count, block_count))
                    return cache.emplace(node.get(), std::nullopt).first->second;
                value.reserve(count);
                value.insert(value.end(), left->begin(), left->end());
                value.insert(value.end(), right->begin(), right->end());
            }
            else
            {
                if (right->size() != 0 &&
                    left->size() > std::numeric_limits<std::size_t>::max() / right->size())
                    return cache.emplace(node.get(), std::nullopt).first->second;
                if (left_maximum >
                    std::numeric_limits<std::size_t>::max() - right_maximum)
                    return cache.emplace(node.get(), std::nullopt).first->second;
                const auto count = left->size() * right->size();
                const auto length = left_maximum + right_maximum;
                if (!fits_shape(length, count, block_count))
                    return cache.emplace(node.get(), std::nullopt).first->second;
                value.reserve(count);
                for (const auto &left_clause : *left)
                {
                    for (const auto &right_clause : *right)
                    {
                        auto clause = left_clause;
                        clause.insert(clause.end(), right_clause.begin(), right_clause.end());
                        value.push_back(std::move(clause));
                    }
                }
            }
            return cache.emplace(node.get(), std::move(value)).first->second;
        }

        [[nodiscard]] std::shared_ptr<const PlanNode> build_plan(
            const std::shared_ptr<const NnfNode> &node,
            const std::vector<std::size_t> &leaf_sources,
            const std::size_t block_count,
            DnfCache &cache,
            bool &uses_fallback)
        {
            auto result = std::make_shared<PlanNode>();
            if (node->kind == PlanKind::literal)
            {
                result->literal = {leaf_sources.at(node->leaf_position), node->negated};
                return result;
            }
            const auto &attempt = bounded_dnf(node, leaf_sources, block_count, cache);
            if (attempt)
            {
                result->kind = PlanKind::local_dnf;
                result->dnf_clauses = *attempt;
                result->padded_clause_length = next_power_of_two(
                    maximum_clause_length(result->dnf_clauses));
                result->padded_clause_count = next_power_of_two(result->dnf_clauses.size());
                return result;
            }
            uses_fallback = true;
            result->kind = node->kind;
            result->children.push_back(build_plan(
                node->left, leaf_sources, block_count, cache, uses_fallback));
            result->children.push_back(build_plan(
                node->right, leaf_sources, block_count, cache, uses_fallback));
            return result;
        }
    }

    CompiledQuery compile_query(
        const pir::common::BooleanQuery &query,
        const std::size_t block_count)
    {
        if (block_count < 2 || !is_power_of_two(block_count))
            throw std::invalid_argument("block_count must be a power of two greater than one");
        std::vector<std::uint32_t> leaves;
        const auto normalized = normalize(query, false, leaves);
        if (leaves.empty()) throw std::invalid_argument("query has no keyword leaves");

        CompiledQuery result;
        result.block_count = block_count;
        result.leaf_count = leaves.size();
        std::vector<std::size_t> leaf_sources;
        leaf_sources.reserve(leaves.size());
        // Pack each distinct keyword once, in first-occurrence order. Repeated keyword
        // leaves then share the same source slot, matching the paper's distinct
        // queried-keyword list KL, so one ciphertext multiplexes B distinct keywords.
        std::unordered_map<std::uint32_t, std::size_t> first_source;
        for (const auto keyword : leaves)
        {
            const auto [entry, inserted] = first_source.emplace(
                keyword, result.packed_keywords.size());
            if (inserted) result.packed_keywords.push_back(keyword);
            leaf_sources.push_back(entry->second);
        }

        // Caching bounded attempts costs O(AST nodes * B) worst-case temporary space,
        // but prevents repeated exponential DNF exploration after an ancestor falls back.
        DnfCache cache;
        result.root = build_plan(
            normalized, leaf_sources, block_count, cache, result.uses_fallback);
        return result;
    }
}
