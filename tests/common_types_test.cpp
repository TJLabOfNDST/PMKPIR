#include "pir/common/bfv.hpp"
#include "pir/common/types.hpp"

#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{
    void require(const bool condition, const std::string &message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    void require_invalid_argument(
        const std::function<void()> &operation,
        const std::string &parameter_name)
    {
        try
        {
            operation();
        }
        catch (const std::invalid_argument &error)
        {
            require(
                std::string(error.what()).find(parameter_name) != std::string::npos,
                "diagnostic must name " + parameter_name);
            return;
        }
        throw std::runtime_error("expected invalid_argument for " + parameter_name);
    }
}

int main()
{
    try
    {
        const pir::common::BfvParameters defaults;
        require(defaults.polynomial_modulus_degree == 16384, "default N must be 16384");
        require(defaults.plain_modulus == 65537, "default t must be 65537");
        require(defaults.block_count == 4, "default B must be 4");
        require(defaults.constant_weight == 2, "default k must be 2");
        require(defaults.minimum_noise_budget_bits == 20, "default noise gate must be 20 bits");
        require(defaults.logical_region_width() == 4096, "default w must be 4096");

        const auto context = pir::common::make_bfv_context(defaults, 16);
        require(context && context->parameters_set(), "default BFV context must be valid");
        require(
            context->first_context_data()->qualifiers().using_batching,
            "default BFV context must support batching");

        auto invalid = defaults;
        invalid.polynomial_modulus_degree = 12000;
        require_invalid_argument(
            [&] { (void)pir::common::make_bfv_context(invalid, 16); },
            "polynomial_modulus_degree");

        invalid = defaults;
        invalid.plain_modulus = 2;
        require_invalid_argument(
            [&] { (void)pir::common::make_bfv_context(invalid, 16); },
            "plain_modulus");

        invalid = defaults;
        invalid.block_count = 3;
        require_invalid_argument(
            [&] { (void)pir::common::make_bfv_context(invalid, 16); },
            "block_count");

        invalid = defaults;
        invalid.constant_weight = 0;
        require_invalid_argument(
            [&] { (void)pir::common::make_bfv_context(invalid, 16); },
            "constant_weight");

        require_invalid_argument(
            [&] { (void)pir::common::make_bfv_context(defaults, 24); },
            "public_domain_bits");

        std::cout << "common_types_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "common_types_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
