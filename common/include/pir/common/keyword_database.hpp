#pragma once

#include "pir/common/dataset.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pir::common
{
    class KeywordDatabase
    {
    public:
        [[nodiscard]] std::size_t keyword_count() const noexcept;
        [[nodiscard]] std::size_t document_count() const noexcept;
        [[nodiscard]] std::size_t fragment_width() const noexcept;
        [[nodiscard]] std::size_t fragment_count() const noexcept;
        [[nodiscard]] std::size_t logical_storage_bytes() const noexcept;
        [[nodiscard]] bool contains(std::size_t keyword, std::size_t document) const;
        void copy_fragment(
            std::size_t keyword,
            std::size_t fragment,
            std::span<std::uint64_t> destination) const;

    private:
        friend KeywordDatabase build_keyword_database(const Dataset &, std::size_t);
        std::size_t keyword_count_ = 0;
        std::size_t document_count_ = 0;
        std::size_t fragment_width_ = 0;
        std::size_t fragment_count_ = 0;
        std::size_t row_word_count_ = 0;
        std::size_t logical_storage_bytes_ = 0;
        std::vector<std::uint64_t> row_major_words_;
    };

    [[nodiscard]] KeywordDatabase build_keyword_database(
        const Dataset &dataset,
        std::size_t fragment_width);
}
