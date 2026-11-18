#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pir::pmkpir
{
    // A codebook for keyword domains wider than 64 bits. Instead of storing dense
    // constant-weight codewords (O(K*w)), it stores the byte identifier and the sparse
    // set of set-bit positions (O(K*k)) for each of the K public keywords.
    class WideKeywordCodebook
    {
    public:
        [[nodiscard]] std::size_t size() const noexcept;
        [[nodiscard]] std::size_t domain_bits() const noexcept;
        [[nodiscard]] std::size_t code_width() const noexcept;
        [[nodiscard]] std::size_t weight() const noexcept;
        [[nodiscard]] std::span<const std::uint8_t> identifier(
            std::size_t keyword) const;
        [[nodiscard]] std::span<const std::size_t> positions(
            std::size_t keyword) const;

    private:
        friend WideKeywordCodebook make_wide_keyword_codebook(
            std::size_t keyword_count,
            std::size_t domain_bits,
            std::size_t code_width,
            std::size_t weight);

        std::size_t domain_bits_ = 0;
        std::size_t code_width_ = 0;
        std::size_t weight_ = 0;
        std::vector<std::vector<std::uint8_t>> identifiers_;
        std::vector<std::vector<std::size_t>> positions_;
    };

    [[nodiscard]] WideKeywordCodebook make_wide_keyword_codebook(
        std::size_t keyword_count,
        std::size_t domain_bits,
        std::size_t code_width,
        std::size_t weight);
}
