#pragma once

#include <cstddef>
#include <vector>

namespace pir::pmkpir
{
    // The interleaved layout of IBPIR / PMKPIR. It maps the B logical sub-blocks
    // (one per batched keyword) onto the 2 x (N/2) BFV batching matrix so that a
    // single row rotation never moves a slot out of its owning sub-block.
    class InterleavedLayout
    {
    public:
        InterleavedLayout(std::size_t polynomial_modulus_degree, std::size_t block_count);

        [[nodiscard]] std::size_t polynomial_modulus_degree() const noexcept;
        [[nodiscard]] std::size_t block_count() const noexcept;
        [[nodiscard]] std::size_t blocks_per_row() const noexcept;
        [[nodiscard]] std::size_t region_width() const noexcept;
        [[nodiscard]] std::size_t slot_index(
            std::size_t block,
            std::size_t region_offset) const;
        [[nodiscard]] std::vector<int> reduction_rotation_steps() const;

    private:
        std::size_t polynomial_modulus_degree_;
        std::size_t block_count_;
        std::size_t blocks_per_row_;
        std::size_t region_width_;
    };
}
