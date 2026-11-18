#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pir::common
{
    struct BfvParameters
    {
        std::size_t polynomial_modulus_degree = 16384;
        std::uint64_t plain_modulus = 65537;
        std::size_t block_count = 4;
        std::size_t constant_weight = 2;
        int minimum_noise_budget_bits = 20;
        std::vector<int> coefficient_modulus_bits;

        [[nodiscard]] std::size_t logical_region_width() const noexcept
        {
            return block_count == 0 ? 0 : polynomial_modulus_degree / block_count;
        }
    };

    struct HomomorphicCounters
    {
        std::size_t ciphertext_multiplications = 0;
        std::size_t plaintext_multiplications = 0;
        std::size_t additions = 0;
        std::size_t galois_applications = 0;
        std::size_t row_rotations = 0;
        std::size_t row_swaps = 0;
        std::size_t relinearizations = 0;
    };
}
