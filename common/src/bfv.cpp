#include "pir/common/bfv.hpp"

#include "pir/common/constant_weight.hpp"

#include <stdexcept>
#include <string>
#include <unordered_set>

namespace pir::common
{
    namespace
    {
        [[nodiscard]] bool is_power_of_two(const std::size_t value) noexcept
        {
            return value != 0 && (value & (value - 1)) == 0;
        }

        [[nodiscard]] std::uint32_t power_mod(
            std::uint64_t base,
            std::size_t exponent,
            const std::uint64_t modulus) noexcept
        {
            std::uint64_t result = 1;
            while (exponent != 0)
            {
                if ((exponent & 1U) != 0) result = (result * base) % modulus;
                base = (base * base) % modulus;
                exponent >>= 1U;
            }
            return static_cast<std::uint32_t>(result);
        }

        void validate_layout(
            const BfvParameters &parameters,
            const std::size_t public_domain_bits)
        {
            if (!is_power_of_two(parameters.polynomial_modulus_degree))
            {
                throw std::invalid_argument(
                    "polynomial_modulus_degree must be a nonzero power of two");
            }
            if (parameters.plain_modulus <= parameters.polynomial_modulus_degree)
            {
                throw std::invalid_argument(
                    "plain_modulus must exceed polynomial_modulus_degree for this layout");
            }
            if (parameters.block_count < 2 ||
                !is_power_of_two(parameters.block_count) ||
                parameters.polynomial_modulus_degree % parameters.block_count != 0)
            {
                throw std::invalid_argument(
                    "block_count must be a power of two that divides polynomial_modulus_degree");
            }
            const std::size_t width = parameters.logical_region_width();
            if (width % 2 != 0)
            {
                throw std::invalid_argument("block_count produces an odd logical region width");
            }
            if (parameters.constant_weight == 0 || parameters.constant_weight > width)
            {
                throw std::invalid_argument(
                    "constant_weight must be in the logical region width");
            }
            if (public_domain_bits == 0)
            {
                throw std::invalid_argument("public_domain_bits must be positive");
            }

            // Exact arbitrary-precision comparison keeps the public-domain validation correct
            // through 2^256 while keeping big integers out of the homomorphic online path.
            if (minimum_constant_weight(width, public_domain_bits) >
                parameters.constant_weight)
            {
                throw std::invalid_argument(
                    "public_domain_bits exceed the constant-weight code capacity");
            }
        }
    }

    std::shared_ptr<seal::SEALContext> make_bfv_context(
        const BfvParameters &parameters,
        const std::size_t public_domain_bits)
    {
        validate_layout(parameters, public_domain_bits);

        seal::EncryptionParameters encryption_parameters(seal::scheme_type::bfv);
        encryption_parameters.set_poly_modulus_degree(
            parameters.polynomial_modulus_degree);
        encryption_parameters.set_coeff_modulus(
            parameters.coefficient_modulus_bits.empty()
                ? seal::CoeffModulus::BFVDefault(
                      parameters.polynomial_modulus_degree,
                      seal::sec_level_type::tc128)
                : seal::CoeffModulus::Create(
                      parameters.polynomial_modulus_degree,
                      parameters.coefficient_modulus_bits));
        encryption_parameters.set_plain_modulus(parameters.plain_modulus);

        auto context = std::make_shared<seal::SEALContext>(
            encryption_parameters, true, seal::sec_level_type::tc128);
        if (!context->parameters_set())
        {
            throw std::invalid_argument(
                "BFV parameters are rejected by SEAL at tc128 security");
        }
        if (!context->first_context_data()->qualifiers().using_batching)
        {
            throw std::invalid_argument(
                "plain_modulus does not support BFV batching");
        }
        return context;
    }

    std::vector<std::uint32_t> galois_elements_for_steps(
        const std::size_t polynomial_modulus_degree,
        const std::span<const int> row_rotation_steps,
        const bool include_row_swap)
    {
        if (!is_power_of_two(polynomial_modulus_degree) ||
            polynomial_modulus_degree > (std::numeric_limits<std::uint32_t>::max() >> 1U))
        {
            throw std::invalid_argument("polynomial_modulus_degree is invalid for Galois keys");
        }
        const std::size_t row_size = polynomial_modulus_degree / 2;
        const std::uint64_t modulus = polynomial_modulus_degree * 2;
        std::vector<std::uint32_t> elements;
        std::unordered_set<std::uint32_t> seen;
        elements.reserve(row_rotation_steps.size() + static_cast<std::size_t>(include_row_swap));
        for (const int step : row_rotation_steps)
        {
            if (step == 0 || step <= -static_cast<int>(row_size) ||
                step >= static_cast<int>(row_size))
            {
                throw std::invalid_argument("row rotation step is outside the batching row");
            }
            const std::size_t exponent = step > 0
                                             ? static_cast<std::size_t>(step)
                                             : row_size - static_cast<std::size_t>(-step);
            const auto element = power_mod(3, exponent, modulus);
            if (seen.insert(element).second) elements.push_back(element);
        }
        if (include_row_swap)
        {
            const auto element = static_cast<std::uint32_t>(modulus - 1);
            if (seen.insert(element).second) elements.push_back(element);
        }
        return elements;
    }
}
