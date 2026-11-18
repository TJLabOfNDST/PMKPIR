#include "pir/common/boolean_query.hpp"
#include "pir/common/dataset.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
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
        pir::common::Dataset dataset;
        dataset.parameters = {4, 3, 2, 0, 7};
        dataset.documents = {
            {0, {0, 1}, {}},
            {1, {1, 2}, {}},
            {2, {0, 2}, {}},
            {3, {}, {}}};

        using Query = pir::common::BooleanQuery;
        const auto query = Query::Or(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Not(Query::Keyword(1))));
        require(
            pir::common::evaluate_query(query, dataset) ==
                std::vector<std::uint8_t>({1, 0, 1, 0}),
            "general Boolean query differs from the hand-derived bitmap");
        require(
            pir::common::leaf_keywords(query) ==
                std::vector<std::uint32_t>({0, 1, 2, 1}),
            "leaf traversal order differs");
        require(
            pir::common::distinct_leaf_keywords(query) ==
                std::vector<std::uint32_t>({0, 1, 2}),
            "distinct leaves must preserve first occurrence");

        const auto pushed = pir::common::push_not_to_leaves(Query::Not(Query::Or(
            Query::Keyword(0), Query::Not(Query::Keyword(1)))));
        require(
            pir::common::is_negation_normal_form(pushed),
            "NOT pushdown must leave negations only on keywords");
        require(
            pir::common::evaluate_query(pushed, dataset) ==
                std::vector<std::uint8_t>({0, 1, 0, 0}),
            "NOT pushdown changed query semantics");

        bool rejected = false;
        try
        {
            (void)pir::common::evaluate_query(Query::Keyword(3), dataset);
        }
        catch (const std::out_of_range &)
        {
            rejected = true;
        }
        require(rejected, "keyword outside the public dataset domain must be rejected");

        std::cout << "boolean_query_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "boolean_query_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
