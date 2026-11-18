#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace pir::common
{
    [[nodiscard]] std::string binomial_decimal(std::size_t width, std::size_t weight);
    [[nodiscard]] std::size_t minimum_constant_weight(
        std::size_t width,
        std::size_t public_domain_bits);
    [[nodiscard]] std::vector<std::size_t> unrank_constant_weight_bytes(
        std::size_t width,
        std::size_t weight,
        std::span<const std::uint8_t> big_endian_rank);
    [[nodiscard]] std::vector<std::size_t> unrank_constant_weight_u64(
        std::size_t width,
        std::size_t weight,
        std::uint64_t rank);
}
