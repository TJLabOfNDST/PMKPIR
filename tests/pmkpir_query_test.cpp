#include "pir/pmkpir/layout.hpp"
#include "pir/pmkpir/query_compiler.hpp"

#include "pir/common/boolean_query.hpp"

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
        const pir::pmkpir::InterleavedLayout layout(32, 4);
        require(layout.region_width() == 8, "w=N/B differs");
        require(layout.blocks_per_row() == 2, "B_row=B/2 differs");
        require(layout.slot_index(0, 3) == 6, "q0 mapping differs");
        require(layout.slot_index(1, 3) == 7, "q1 mapping differs");
        require(layout.slot_index(2, 3) == 22, "q2 mapping differs");
        require(layout.slot_index(3, 3) == 23, "q3 mapping differs");
        require(
            layout.reduction_rotation_steps() == std::vector<int>({2, 4, 8}),
            "PMKPIR reduction steps differ");
        std::set<std::size_t> occupied;
        for (std::size_t block = 0; block < layout.block_count(); ++block)
            for (std::size_t offset = 0; offset < layout.region_width(); ++offset)
                require(
                    occupied.insert(layout.slot_index(block, offset)).second,
                    "logical regions overlap");

        require(
            pir::pmkpir::InterleavedLayout(32, 2).reduction_rotation_steps() ==
                std::vector<int>({1, 2, 4, 8}),
            "B=2 reduction steps differ");
        require(
            pir::pmkpir::InterleavedLayout(32, 8).reduction_rotation_steps() ==
                std::vector<int>({4, 8}),
            "B=8 reduction steps differ");

        using Query = pir::common::BooleanQuery;
        const auto exact = Query::Or(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Not(Query::Keyword(3))));
        const auto compiled = pir::pmkpir::compile_query(exact, 4);
        require(compiled.leaf_count == 4, "leaf count differs");
        require(
            compiled.packed_keywords == std::vector<std::uint32_t>({0, 1, 2, 3}),
            "packed keywords differ");
        require(compiled.root->kind == pir::pmkpir::PlanKind::local_dnf, "exact-B DNF must be accepted");
        require(compiled.root->padded_clause_length == 2, "DNF padded length differs");
        require(compiled.root->padded_clause_count == 2, "DNF padded count differs");
        require(!compiled.uses_fallback, "accepted local DNF must not report fallback");
        require(compiled.root->dnf_clauses[1][1].negated, "NOT must be pushed to a literal");

        // The keyword list KL holds distinct keywords only, so repeated leaves
        // must share one source slot while distinct keywords keep distinct slots.
        const auto repeated = Query::Or(
            Query::And(Query::Keyword(0), Query::Keyword(0)),
            Query::And(Query::Keyword(1), Query::Keyword(0)));
        const auto repeated_compiled = pir::pmkpir::compile_query(repeated, 4);
        require(
            repeated_compiled.packed_keywords == std::vector<std::uint32_t>({0, 1}),
            "repeated keywords must be packed once");
        require(
            repeated_compiled.root->dnf_clauses[0][0].source_index == 0 &&
                repeated_compiled.root->dnf_clauses[0][1].source_index == 0,
            "repeated literals must share a source");
        require(
            repeated_compiled.root->dnf_clauses[1][0].source_index == 1 &&
                repeated_compiled.root->dnf_clauses[1][1].source_index == 0,
            "distinct keywords must keep distinct sources");

        const auto too_large = Query::Or(
            Query::Or(
                Query::And(Query::Keyword(0), Query::Keyword(1)),
                Query::And(Query::Keyword(2), Query::Keyword(3))),
            Query::And(Query::Keyword(4), Query::Keyword(5)));
        const auto fallback = pir::pmkpir::compile_query(too_large, 4);
        require(fallback.uses_fallback, "padded DNF workspace above B must fall back");
        require(fallback.root->kind == pir::pmkpir::PlanKind::logical_or, "fallback must preserve the AST operator");

        bool rejected = false;
        try
        {
            (void)pir::pmkpir::InterleavedLayout(32, 3);
        }
        catch (const std::invalid_argument &)
        {
            rejected = true;
        }
        require(rejected, "non-power-of-two B must be rejected");

        std::cout << "pmkpir_query_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "pmkpir_query_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
