#pragma once

#include "pir/common/types.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace pir::common
{
    [[nodiscard]] std::shared_ptr<seal::SEALContext> make_bfv_context(
        const BfvParameters &parameters,
        std::size_t public_domain_bits);

    [[nodiscard]] std::vector<std::uint32_t> galois_elements_for_steps(
        std::size_t polynomial_modulus_degree,
        std::span<const int> row_rotation_steps,
        bool include_row_swap);
}
