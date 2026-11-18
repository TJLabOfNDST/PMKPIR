#include "pir/pmkpir/protocol.hpp"

#include "pir/common/boolean_query.hpp"
#include "pir/common/dataset.hpp"
#include "pir/pmkpir/query_compiler.hpp"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace
{
    void require(const bool condition, const char *message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    class TemporaryDirectory
    {
    public:
        TemporaryDirectory()
            : path_(std::filesystem::temp_directory_path() / "pir-pmkpir-cache-test")
        {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
            std::filesystem::create_directories(path_);
        }
        ~TemporaryDirectory()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }
        [[nodiscard]] const std::filesystem::path &path() const noexcept { return path_; }

    private:
        std::filesystem::path path_;
    };
}

int main()
{
    try
    {
        const pir::common::BfvParameters parameters;
        pir::common::Dataset dataset;
        dataset.parameters = {5, 6, 2, 0, 11};
        dataset.documents = {
            {0, {0, 1}, {}},
            {1, {1, 2}, {}},
            {2, {0, 2}, {}},
            {3, {3, 4}, {}},
            {4, {2, 4, 5}, {}}};

        pir::pmkpir::Client client(parameters, 16);
        pir::pmkpir::Server server(
            parameters,
            client.context(),
            client.relinearization_keys(),
            client.galois_keys());
        const auto preprocessed = server.preprocess(dataset);
        require(preprocessed.setup_metrics().keyword_encode_ms > 0,
                "PMKPIR keyword setup timing must be measured");
        require(preprocessed.setup_metrics().bitmap_build_ms > 0,
                "PMKPIR bitmap setup timing must be measured");
        require(preprocessed.keyword_count() == 6, "PMKPIR keyword count differs");
        require(preprocessed.fragment_count() == 1, "small PMKPIR database must use one fragment");

        TemporaryDirectory temporary;
        const auto cache_path = temporary.path() / "pmkpir.pirplain";
        server.save_preprocessed(preprocessed, cache_path, "dataset-sha-fixture");
        const auto loaded = server.load_preprocessed(
            cache_path,
            "dataset-sha-fixture",
            dataset.parameters.keyword_count,
            dataset.documents.size());

        using Query = pir::common::BooleanQuery;
        const auto general = Query::Or(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Not(Query::Keyword(1))));
        {
            const auto compiled = pir::pmkpir::compile_query(general, 4);
            const auto encrypted_query = client.create_query(compiled);
            require(encrypted_query.ciphertexts.size() == 1, "four sources must fit one PMKPIR container");
            const auto encrypted_result = server.evaluate(encrypted_query, loaded);
            const auto result = client.decrypt_selection(encrypted_result, dataset.documents.size());
            require(
                result.bitmap == std::vector<std::uint8_t>({1, 0, 1, 0, 1}),
                "PMKPIR general Boolean result differs");
            require(result.minimum_noise_budget_bits >= 20, "PMKPIR noise gate failed");
        }

        const auto repeated = Query::And(
            Query::And(Query::Keyword(0), Query::Keyword(0)),
            Query::And(
                Query::Keyword(1),
                Query::And(Query::Keyword(0), Query::Keyword(1))));
        const auto repeated_query = client.create_query(pir::pmkpir::compile_query(repeated, 4));
        require(repeated_query.ciphertexts.size() == 1,
                "two distinct keywords must pack into one PMKPIR container");
        require(
            client.decrypt_selection(
                server.evaluate(repeated_query, loaded), dataset.documents.size()).bitmap ==
                pir::common::evaluate_query(repeated, dataset),
            "repeated-keyword PMKPIR result differs from plaintext evaluation");

        const auto fallback_expression = Query::Or(
            Query::Or(
                Query::And(Query::Keyword(0), Query::Keyword(1)),
                Query::And(Query::Keyword(2), Query::Keyword(3))),
            Query::And(Query::Keyword(4), Query::Keyword(5)));
        const auto fallback_query = client.create_query(pir::pmkpir::compile_query(
            fallback_expression, 4));
        require(
            client.decrypt_selection(
                server.evaluate(fallback_query, loaded), dataset.documents.size()).bitmap ==
                std::vector<std::uint8_t>({1, 0, 0, 0, 1}),
            "PMKPIR fallback Boolean result differs");

        const auto missing_query = client.create_query(pir::pmkpir::compile_query(
            Query::Keyword(7), 4));
        const auto missing_answer = server.evaluate(missing_query, loaded);
        require(
            client.decrypt_selection(missing_answer, dataset.documents.size()).bitmap ==
                std::vector<std::uint8_t>({0, 0, 0, 0, 0}),
            "missing public keyword must return an empty PMKPIR bitmap");
        const auto &scan = missing_answer.metrics.scan_operations;
        require(scan.ciphertext_multiplications == 6, "PMKPIR scan ct-ct formula differs");
        require(scan.relinearizations == 1, "PMKPIR aggregate-root relinearization formula differs");
        require(scan.plaintext_multiplications == 12, "PMKPIR scan ct-pt formula differs");
        require(scan.row_rotations == 72, "PMKPIR scan rotation formula differs");

        auto boundary_parameters = dataset.parameters;
        boundary_parameters.document_count = 4097;
        boundary_parameters.keyword_count = 8;
        boundary_parameters.keywords_per_document = 4;
        const auto boundary = pir::common::generate_conjunction_dataset(
            boundary_parameters, 4, 8);
        const auto boundary_database = server.preprocess(boundary);
        require(boundary_database.fragment_count() == 2, "M=w+1 must use two PMKPIR fragments");
        const auto boundary_query_plan = Query::And(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Keyword(3)));
        const auto boundary_query = client.create_query(pir::pmkpir::compile_query(
            boundary_query_plan, 4));
        const auto boundary_answer = server.evaluate(boundary_query, boundary_database);
        require(
            boundary_answer.fragments.size() == 1,
            "M=w+1 must pack the two PMKPIR fragments into one response");
        require(
            boundary_answer.metrics.boolean_operations.ciphertext_multiplications == 3,
            "four-keyword packed conjunction must use three Boolean multiplications");
        require(
            boundary_answer.metrics.boolean_operations.relinearizations == 3,
            "four-keyword packed conjunction must use three Boolean relinearizations");
        const auto boundary_result = client.decrypt_selection(
            boundary_answer, boundary.documents.size());
        require(
            boundary_result.bitmap == pir::common::evaluate_query(boundary_query_plan, boundary),
            "packed cross-fragment PMKPIR query result differs");

        const auto boundary_general_plan = Query::Or(
            Query::And(Query::Keyword(0), Query::Not(Query::Keyword(1))),
            Query::And(
                Query::Keyword(2),
                Query::Or(Query::Keyword(3), Query::Keyword(4))));
        const auto boundary_general_query = client.create_query(pir::pmkpir::compile_query(
            boundary_general_plan, 4));
        require(
            boundary_general_query.ciphertexts.size() == 2,
            "five distinct keywords must use two PMKPIR containers");
        const auto boundary_general_answer = server.evaluate(
            boundary_general_query, boundary_database);
        require(
            boundary_general_answer.fragments.size() == 1,
            "multi-container cross-fragment query must return one packed response");
        require(
            client.decrypt_selection(
                boundary_general_answer, boundary.documents.size()).bitmap ==
                pir::common::evaluate_query(boundary_general_plan, boundary),
            "packed multi-container NOT/OR query result differs");

        auto full_ciphertext_parameters = dataset.parameters;
        full_ciphertext_parameters.document_count = parameters.polynomial_modulus_degree;
        full_ciphertext_parameters.keyword_count = 8;
        full_ciphertext_parameters.keywords_per_document = 4;
        const auto full_ciphertext_dataset = pir::common::generate_conjunction_dataset(
            full_ciphertext_parameters, 4, 8);
        const auto full_ciphertext_database = server.preprocess(full_ciphertext_dataset);
        require(
            full_ciphertext_database.fragment_count() == parameters.block_count,
            "M=N must use exactly B PMKPIR database fragments");
        const auto full_ciphertext_plan = Query::And(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Keyword(3)));
        const auto full_ciphertext_query = client.create_query(pir::pmkpir::compile_query(
            full_ciphertext_plan, 4));
        const auto full_ciphertext_answer = server.evaluate(
            full_ciphertext_query, full_ciphertext_database);
        require(
            full_ciphertext_answer.fragments.size() == 1,
            "M=N must return exactly one packed PMKPIR response");
        require(
            client.decrypt_selection(
                full_ciphertext_answer, full_ciphertext_dataset.documents.size()).bitmap ==
                pir::common::evaluate_query(full_ciphertext_plan, full_ciphertext_dataset),
            "M=N packed PMKPIR query result differs");
        require(
            full_ciphertext_answer.metrics.boolean_operations.plaintext_multiplications == 8,
            "B=4 butterfly transpose must use eight Boolean plaintext multiplications");
        require(
            full_ciphertext_answer.metrics.boolean_operations.row_rotations +
                    full_ciphertext_answer.metrics.boolean_operations.row_swaps == 8,
            "B=4 butterfly transpose must use eight Boolean slot moves");

        const auto full_general_plan = Query::Or(
            Query::And(Query::Keyword(0), Query::Not(Query::Keyword(1))),
            Query::And(Query::Keyword(2), Query::Keyword(3)));
        const auto full_general_query = client.create_query(pir::pmkpir::compile_query(
            full_general_plan, 4));
        const auto full_general_answer = server.evaluate(
            full_general_query, full_ciphertext_database);
        require(
            client.decrypt_selection(
                full_general_answer, full_ciphertext_dataset.documents.size()).bitmap ==
                pir::common::evaluate_query(full_general_plan, full_ciphertext_dataset),
            "M=N packed NOT/OR PMKPIR query result differs");

        const auto partial_container_plan = Query::Keyword(0);
        const auto partial_container_query = client.create_query(pir::pmkpir::compile_query(
            partial_container_plan, 4));
        const auto partial_container_answer = server.evaluate(
            partial_container_query, full_ciphertext_database);
        require(
            client.decrypt_selection(
                partial_container_answer, full_ciphertext_dataset.documents.size()).bitmap ==
                pir::common::evaluate_query(
                    partial_container_plan, full_ciphertext_dataset),
            "M=N partial-container PMKPIR fallback differs");

        full_ciphertext_parameters.document_count = parameters.polynomial_modulus_degree + 1;
        const auto multiple_response_dataset = pir::common::generate_conjunction_dataset(
            full_ciphertext_parameters, 4, 8);
        const auto multiple_response_database = server.preprocess(multiple_response_dataset);
        const auto multiple_response_answer = server.evaluate(
            full_ciphertext_query, multiple_response_database);
        require(
            multiple_response_answer.fragments.size() == 2,
            "M=N+1 must return two packed PMKPIR responses");
        require(
            client.decrypt_selection(
                multiple_response_answer, multiple_response_dataset.documents.size()).bitmap ==
                pir::common::evaluate_query(full_ciphertext_plan, multiple_response_dataset),
            "M=N+1 packed PMKPIR query result differs");

        std::cout << "pmkpir_protocol_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "pmkpir_protocol_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
