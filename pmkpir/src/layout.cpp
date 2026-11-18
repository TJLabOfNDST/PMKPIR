#include "pir/pmkpir/layout.hpp"

#include <limits>
#include <stdexcept>

namespace pir::pmkpir
{
    namespace
    {
        [[nodiscard]] bool is_power_of_two(const std::size_t value) noexcept
        {
            return value != 0 && (value & (value - 1)) == 0;
        }
    }

    InterleavedLayout::InterleavedLayout(
        const std::size_t polynomial_modulus_degree,
        const std::size_t block_count)
        : polynomial_modulus_degree_(polynomial_modulus_degree),
          block_count_(block_count),
          blocks_per_row_(block_count / 2),
          region_width_(block_count == 0 ? 0 : polynomial_modulus_degree / block_count)
    {
        if (!is_power_of_two(polynomial_modulus_degree_) ||
            block_count_ < 2 || !is_power_of_two(block_count_) ||
            polynomial_modulus_degree_ % block_count_ != 0)
        {
            throw std::invalid_argument(
                "N and B must be powers of two, B>=2, and B must divide N");
        }
        if (polynomial_modulus_degree_ >
            static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::invalid_argument("N exceeds the SEAL rotation-step integer range");
        }
    }

    std::size_t InterleavedLayout::polynomial_modulus_degree() const noexcept
    {
        return polynomial_modulus_degree_;
    }
    std::size_t InterleavedLayout::block_count() const noexcept { return block_count_; }
    std::size_t InterleavedLayout::blocks_per_row() const noexcept { return blocks_per_row_; }
    std::size_t InterleavedLayout::region_width() const noexcept { return region_width_; }

    std::size_t InterleavedLayout::slot_index(
        const std::size_t block,
        const std::size_t region_offset) const
    {
        if (block >= block_count_) throw std::out_of_range("PMKPIR block is out of range");
        if (region_offset >= region_width_)
            throw std::out_of_range("PMKPIR region offset is out of range");
        const std::size_t row = block / blocks_per_row_;
        const std::size_t column = block % blocks_per_row_ +
                                   region_offset * blocks_per_row_;
        return row * (polynomial_modulus_degree_ / 2) + column;
    }

    std::vector<int> InterleavedLayout::reduction_rotation_steps() const
    {
        std::vector<int> steps;
        for (std::size_t distance = 1; distance < region_width_; distance <<= 1U)
            steps.push_back(static_cast<int>(distance * blocks_per_row_));
        return steps;
    }
}
