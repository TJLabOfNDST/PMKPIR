#include "pir/pmkpir/wide_keyword_codebook.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

    template <typename Exception, typename Function>
    void require_throws(Function &&function, const char *message)
    {
        try
        {
            function();
        }
        catch (const Exception &)
        {
            return;
        }
        throw std::runtime_error(message);
    }
}

int main()
{
    try
    {
        constexpr std::size_t keyword_count = 64;
        constexpr std::size_t code_width = 4096;
        constexpr std::array<std::size_t, 6> domain_bits{8, 16, 32, 64, 128, 256};
        constexpr std::array<std::size_t, 6> expected_weights{1, 2, 3, 7, 14, 31};

        for (std::size_t config = 0; config < domain_bits.size(); ++config)
        {
            const auto codebook = pir::pmkpir::make_wide_keyword_codebook(
                keyword_count,
                domain_bits[config],
                code_width,
                expected_weights[config]);
            const auto repeated = pir::pmkpir::make_wide_keyword_codebook(
                keyword_count,
                domain_bits[config],
                code_width,
                expected_weights[config]);

            require(codebook.size() == keyword_count, "wide codebook row count differs");
            require(codebook.domain_bits() == domain_bits[config], "wide codebook domain differs");
            require(codebook.code_width() == code_width, "wide codebook width differs");
            require(codebook.weight() == expected_weights[config], "wide codebook weight differs");

            std::set<std::vector<std::uint8_t>> unique_identifiers;
            std::set<std::vector<std::size_t>> unique_positions;
            for (std::size_t keyword = 0; keyword < keyword_count; ++keyword)
            {
                const auto identifier = codebook.identifier(keyword);
                const auto positions = codebook.positions(keyword);
                require(
                    identifier.size() == domain_bits[config] / 8,
                    "wide identifier byte length differs");
                require(
                    positions.size() == expected_weights[config],
                    "wide codeword weight differs");
                require(
                    std::is_sorted(positions.begin(), positions.end()),
                    "wide codeword positions must be sorted");
                require(
                    positions.empty() || positions.back() < code_width,
                    "wide codeword position exceeds width");
                require(
                    std::vector<std::uint8_t>(identifier.begin(), identifier.end()) ==
                        std::vector<std::uint8_t>(
                            repeated.identifier(keyword).begin(),
                            repeated.identifier(keyword).end()),
                    "wide identifier construction must be deterministic");
                unique_identifiers.emplace(identifier.begin(), identifier.end());
                unique_positions.emplace(positions.begin(), positions.end());
            }
            require(
                unique_identifiers.size() == keyword_count,
                "collision resolution must keep public identifiers unique");
            require(
                unique_positions.size() == keyword_count,
                "wide public identifiers must map to unique codewords");

            if (domain_bits[config] == 256)
            {
                const auto identifier = codebook.identifier(0);
                require(
                    std::any_of(identifier.begin(), identifier.begin() + 16, [](const auto byte) {
                        return byte != 0;
                    }),
                    "256-bit identifiers must exercise the high 128 bits");
            }
        }

        require_throws<std::invalid_argument>(
            [] { (void)pir::pmkpir::make_wide_keyword_codebook(0, 8, 4096, 1); },
            "zero keyword count must be rejected");
        require_throws<std::invalid_argument>(
            [] { (void)pir::pmkpir::make_wide_keyword_codebook(64, 7, 4096, 1); },
            "non-byte-aligned domains must be rejected");
        require_throws<std::invalid_argument>(
            [] { (void)pir::pmkpir::make_wide_keyword_codebook(64, 24, 4096, 2); },
            "undocumented domain widths must be rejected");
        require_throws<std::invalid_argument>(
            [] { (void)pir::pmkpir::make_wide_keyword_codebook(64, 16, 4096, 1); },
            "insufficient constant-weight capacity must be rejected");
        require_throws<std::invalid_argument>(
            [] { (void)pir::pmkpir::make_wide_keyword_codebook(257, 8, 4096, 1); },
            "keyword count larger than the public domain must be rejected");
        require_throws<std::out_of_range>(
            [] {
                const auto codebook =
                    pir::pmkpir::make_wide_keyword_codebook(64, 8, 4096, 1);
                (void)codebook.identifier(64);
            },
            "out-of-range codebook lookup must be rejected");

        std::cout << "wide_keyword_codebook_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "wide_keyword_codebook_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
