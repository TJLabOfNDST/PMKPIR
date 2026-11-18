#include "pir/common/constant_weight.hpp"

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
        require(pir::common::binomial_decimal(5, 2) == "10", "C(5,2) must equal 10");
        require(pir::common::binomial_decimal(4096, 0) == "1", "C(n,0) must equal 1");
        require(pir::common::minimum_constant_weight(4096, 8) == 1, "2^8 needs k=1");
        require(pir::common::minimum_constant_weight(4096, 16) == 2, "2^16 needs k=2");
        require(pir::common::minimum_constant_weight(4096, 32) == 3, "2^32 needs k=3");
        require(pir::common::minimum_constant_weight(4096, 64) == 7, "2^64 needs k=7");
        require(pir::common::minimum_constant_weight(4096, 128) == 14, "2^128 needs k=14");
        require(pir::common::minimum_constant_weight(4096, 256) == 31, "2^256 needs k=31");

        const std::vector<std::vector<std::size_t>> expected{
            {0, 1}, {0, 2}, {0, 3}, {0, 4}, {1, 2},
            {1, 3}, {1, 4}, {2, 3}, {2, 4}, {3, 4}};
        std::set<std::vector<std::size_t>> unique;
        for (std::uint64_t rank = 0; rank < expected.size(); ++rank)
        {
            const auto code = pir::common::unrank_constant_weight_u64(5, 2, rank);
            require(code == expected[rank], "lexicographic constant-weight unranking differs");
            unique.insert(code);
        }
        require(unique.size() == expected.size(), "constant-weight codes must be unique");

        const std::vector<std::uint8_t> rank_2_to_255(32, 0xff);
        const auto wide_code = pir::common::unrank_constant_weight_bytes(
            4096, 31, rank_2_to_255);
        require(wide_code.size() == 31, "wide rank must produce exactly k positions");
        require(wide_code.back() < 4096, "wide rank position exceeds code width");

        bool rejected = false;
        try
        {
            (void)pir::common::unrank_constant_weight_u64(5, 2, 10);
        }
        catch (const std::out_of_range &)
        {
            rejected = true;
        }
        require(rejected, "rank equal to C(w,k) must be rejected");

        std::cout << "constant_weight_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "constant_weight_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
