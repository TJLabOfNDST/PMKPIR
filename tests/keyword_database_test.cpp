#include "pir/common/keyword_database.hpp"

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
        dataset.parameters = {5, 3, 1, 0, 11};
        dataset.documents = {
            {0, {0}, {}},
            {1, {1}, {}},
            {2, {0, 2}, {}},
            {3, {}, {}},
            {4, {2}, {}}};

        const auto database = pir::common::build_keyword_database(dataset, 4);
        require(database.keyword_count() == 3, "keyword row count differs");
        require(database.document_count() == 5, "document count differs");
        require(database.fragment_width() == 4, "fragment width differs");
        require(database.fragment_count() == 2, "fragment count must ceil-divide M/w");
        require(database.logical_storage_bytes() == 2, "logical bitmap bytes must ceil(K*M/8)");
        require(database.contains(0, 0), "keyword 0 must contain document 0");
        require(database.contains(0, 2), "keyword 0 must contain document 2");
        require(!database.contains(0, 1), "keyword 0 must not contain document 1");
        require(database.contains(2, 4), "keyword 2 must contain document 4");

        std::vector<std::uint64_t> slots(4, 9);
        database.copy_fragment(2, 0, slots);
        require(slots == std::vector<std::uint64_t>({0, 0, 1, 0}), "first fragment differs");
        database.copy_fragment(2, 1, slots);
        require(slots == std::vector<std::uint64_t>({1, 0, 0, 0}), "last fragment padding differs");

        bool rejected = false;
        try
        {
            (void)database.contains(3, 0);
        }
        catch (const std::out_of_range &)
        {
            rejected = true;
        }
        require(rejected, "keyword row outside the database must be rejected");

        std::cout << "keyword_database_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "keyword_database_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
