#include "pir/pmkpir/wide_keyword_codebook.hpp"

#include "pir/common/constant_weight.hpp"
#include "pir/common/hash.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace pir::pmkpir
{
    namespace
    {
        constexpr std::array<std::size_t, 6> supported_domain_bits{
            8, 16, 32, 64, 128, 256};

        void write_u32_big_endian(
            std::array<std::uint8_t, 8> &input,
            const std::size_t offset,
            const std::uint32_t value) noexcept
        {
            for (std::size_t byte = 0; byte < 4; ++byte)
            {
                input[offset + byte] = static_cast<std::uint8_t>(
                    (value >> ((3U - byte) * 8U)) & 0xffU);
            }
        }

        [[nodiscard]] std::string byte_key(
            const std::vector<std::uint8_t> &identifier)
        {
            return {
                reinterpret_cast<const char *>(identifier.data()),
                identifier.size()};
        }

        void validate_inputs(
            const std::size_t keyword_count,
            const std::size_t domain_bits,
            const std::size_t code_width,
            const std::size_t weight)
        {
            if (keyword_count == 0)
                throw std::invalid_argument("wide codebook keyword_count must be positive");
            if (!std::ranges::binary_search(supported_domain_bits, domain_bits))
                throw std::invalid_argument("wide codebook domain_bits are not a supported value");
            if (domain_bits < std::numeric_limits<std::size_t>::digits &&
                keyword_count > (std::size_t{1} << domain_bits))
            {
                throw std::invalid_argument("wide codebook has more keywords than the public domain");
            }

            const std::vector<std::uint8_t> maximum_rank(domain_bits / 8, 0xffU);
            try
            {
                (void)pir::common::unrank_constant_weight_bytes(
                    code_width, weight, maximum_rank);
            }
            catch (const std::out_of_range &)
            {
                throw std::invalid_argument(
                    "wide codebook constant-weight capacity is smaller than the public domain");
            }
        }
    }

    std::size_t WideKeywordCodebook::size() const noexcept
    {
        return identifiers_.size();
    }

    std::size_t WideKeywordCodebook::domain_bits() const noexcept
    {
        return domain_bits_;
    }

    std::size_t WideKeywordCodebook::code_width() const noexcept
    {
        return code_width_;
    }

    std::size_t WideKeywordCodebook::weight() const noexcept
    {
        return weight_;
    }

    std::span<const std::uint8_t> WideKeywordCodebook::identifier(
        const std::size_t keyword) const
    {
        if (keyword >= identifiers_.size())
            throw std::out_of_range("wide codebook keyword is outside the public domain rows");
        return identifiers_[keyword];
    }

    std::span<const std::size_t> WideKeywordCodebook::positions(
        const std::size_t keyword) const
    {
        if (keyword >= positions_.size())
            throw std::out_of_range("wide codebook keyword is outside the public domain rows");
        return positions_[keyword];
    }

    WideKeywordCodebook make_wide_keyword_codebook(
        const std::size_t keyword_count,
        const std::size_t domain_bits,
        const std::size_t code_width,
        const std::size_t weight)
    {
        validate_inputs(keyword_count, domain_bits, code_width, weight);

        WideKeywordCodebook result;
        result.domain_bits_ = domain_bits;
        result.code_width_ = code_width;
        result.weight_ = weight;
        result.identifiers_.reserve(keyword_count);
        result.positions_.reserve(keyword_count);

        std::unordered_set<std::string> used_identifiers;
        used_identifiers.reserve(keyword_count);
        for (std::size_t keyword = 0; keyword < keyword_count; ++keyword)
        {
            std::uint32_t counter = 0;
            std::vector<std::uint8_t> identifier;
            while (true)
            {
                std::array<std::uint8_t, 8> input{};
                write_u32_big_endian(input, 0, static_cast<std::uint32_t>(keyword));
                write_u32_big_endian(input, 4, counter);
                auto digest = pir::common::sha256(
                    "pmkpir-wide-public-keyword-v1", input);
                identifier.assign(
                    digest.begin(),
                    digest.begin() + static_cast<std::ptrdiff_t>(domain_bits / 8));
                if (used_identifiers.insert(byte_key(identifier)).second) break;
                if (counter == std::numeric_limits<std::uint32_t>::max())
                    throw std::runtime_error("wide codebook collision counter exhausted");
                ++counter;
            }

            result.positions_.push_back(pir::common::unrank_constant_weight_bytes(
                code_width, weight, identifier));
            result.identifiers_.push_back(std::move(identifier));
        }

        // Sparse positions use O(Kk) resident space instead of O(Kw) dense codewords.
        return result;
    }
}
