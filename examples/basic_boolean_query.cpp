#include "pir/common/boolean_query.hpp"
#include "pir/common/dataset.hpp"
#include "pir/pmkpir/protocol.hpp"
#include "pir/pmkpir/query_compiler.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>

// End-to-end demonstration of a private Boolean retrieval with PMKPIR.
//
// The flow mirrors a real deployment split across two parties:
//   1. The client builds a public Boolean query, generates BFV keys, and encrypts
//      the query keywords under the interleaved batching layout.
//   2. The server preprocesses the document collection into constant-weight codes
//      and inverted bitmaps, then evaluates the encrypted query homomorphically.
//   3. The client decrypts a single packed bitmap of matching document indices.
//
// The retrieved bitmap is checked against a plaintext evaluation of the same query.
int main()
{
    try
    {
        // 1. Build a tiny document collection: 5 documents over a 6-keyword domain.
        //    DatasetParameters fields are {document_count, keyword_count,
        //    keywords_per_document, payload_bytes, seed}.
        pir::common::Dataset dataset;
        dataset.parameters = {5, 6, 2, 0, 11};
        dataset.documents = {
            {0, {0, 1}, {}},
            {1, {1, 2}, {}},
            {2, {0, 2}, {}},
            {3, {3, 4}, {}},
            {4, {2, 4, 5}, {}}};

        // 2. The Boolean query: (k0 AND k1) OR (k2 AND NOT k1).
        using Query = pir::common::BooleanQuery;
        const auto query = Query::Or(
            Query::And(Query::Keyword(0), Query::Keyword(1)),
            Query::And(Query::Keyword(2), Query::Not(Query::Keyword(1))));

        // 3. Ground truth computed directly on the plaintext dataset.
        const auto expected = pir::common::evaluate_query(query, dataset);

        // 4. Instantiate the two protocol parties.
        const pir::common::BfvParameters parameters;
        pir::pmkpir::Client client(parameters, 16);
        pir::pmkpir::Server server(
            parameters,
            client.context(),
            client.relinearization_keys(),
            client.galois_keys());
        const auto database = server.preprocess(dataset);

        // 5. Run the private protocol end to end.
        const auto compiled = pir::pmkpir::compile_query(query, parameters.block_count);
        const auto encrypted_query = client.create_query(compiled);
        const auto selection = server.evaluate(encrypted_query, database);
        const auto result = client.decrypt_selection(selection, dataset.documents.size());

        // 6. Compare the private result with the plaintext ground truth.
        const bool matches = result.bitmap == expected;

        std::cout << "Expected bitmap : ";
        for (const auto bit : expected) std::cout << static_cast<int>(bit);
        std::cout << "\nRetrieved bitmap: ";
        for (const auto bit : result.bitmap) std::cout << static_cast<int>(bit);
        std::cout << "\nMinimum noise budget: " << result.minimum_noise_budget_bits
                  << " bits\n";
        std::cout << (matches ? "pmkpir_example: PASS" : "pmkpir_example: FAIL") << '\n';
        return matches ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    catch (const std::exception &error)
    {
        std::cerr << "pmkpir_example: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
