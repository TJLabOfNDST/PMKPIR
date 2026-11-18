#include "pir/pmkpir/protocol.hpp"

#include "pir/common/boolean_query.hpp"
#include "pir/common/dataset.hpp"
#include "pir/pmkpir/query_compiler.hpp"
#include "pir/pmkpir/wide_keyword_codebook.hpp"

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

    template <typename Exception, typename Function>
    void require_throws(Function &&function, const char *message)
    {
        try
        {
            function();
        }
        catch (const Exception &)
        {
            return;
        }
        throw std::runtime_error(message);
    }
}

int main()
{
    try
    {
        pir::common::BfvParameters parameters;
        parameters.constant_weight = 31;
        pir::common::Dataset dataset;
        dataset.parameters = {5, 6, 2, 0, 11};
        dataset.documents = {
            {0, {0, 1}, {}},
            {1, {1, 2}, {}},
            {2, {0, 2}, {}},
            {3, {3, 4}, {}},
            {4, {2, 4, 5}, {}}};

        const auto codebook = pir::pmkpir::make_wide_keyword_codebook(
            dataset.parameters.keyword_count,
            256,
            parameters.logical_region_width(),
            parameters.constant_weight);
        pir::pmkpir::Client client(parameters, 256);
        pir::pmkpir::Server server(
            parameters,
            client.context(),
            client.relinearization_keys(),
            client.galois_keys());

        using Query = pir::common::BooleanQuery;
        const auto expression = Query::And(Query::Keyword(0), Query::Keyword(1));
        const auto compiled = pir::pmkpir::compile_query(
            expression, parameters.block_count);
        const auto encrypted_query = client.create_query(compiled, codebook);
        const auto database = server.preprocess(dataset, codebook);
        const auto answer = server.evaluate(encrypted_query, database);
        const auto result = client.decrypt_selection(answer, dataset.documents.size());

        require(
            result.bitmap == pir::common::evaluate_query(expression, dataset),
            "256-bit PMKPIR result differs from plaintext evaluation");
        require(
            result.minimum_noise_budget_bits >= parameters.minimum_noise_budget_bits,
            "256-bit PMKPIR result is below the noise gate");

        const auto short_codebook = pir::pmkpir::make_wide_keyword_codebook(
            5, 256, parameters.logical_region_width(), parameters.constant_weight);
        require_throws<std::invalid_argument>(
            [&] { (void)server.preprocess(dataset, short_codebook); },
            "codebook row mismatch must be rejected");

        const auto wrong_width = pir::pmkpir::make_wide_keyword_codebook(
            dataset.parameters.keyword_count, 256, 8192, parameters.constant_weight);
        require_throws<std::invalid_argument>(
            [&] { (void)server.preprocess(dataset, wrong_width); },
            "codebook width mismatch must be rejected");

        const auto wrong_weight = pir::pmkpir::make_wide_keyword_codebook(
            dataset.parameters.keyword_count,
            256,
            parameters.logical_region_width(),
            parameters.constant_weight + 1);
        require_throws<std::invalid_argument>(
            [&] { (void)client.create_query(compiled, wrong_weight); },
            "codebook weight mismatch must be rejected");

        const auto missing_compiled = pir::pmkpir::compile_query(
            Query::Keyword(7),
            parameters.block_count);
        require_throws<std::out_of_range>(
            [&] { (void)client.create_query(missing_compiled, codebook); },
            "query keyword outside the codebook must be rejected");

        std::cout << "pmkpir_wide_domain_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "pmkpir_wide_domain_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
