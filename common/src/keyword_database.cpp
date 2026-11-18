#include "pir/common/keyword_database.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <unordered_set>

namespace pir::common
{
    namespace
    {
        [[nodiscard]] std::size_t ceil_divide(
            const std::size_t value,
            const std::size_t divisor)
        {
            if (divisor == 0) throw std::invalid_argument("fragment_width must be positive");
            return value / divisor + static_cast<std::size_t>(value % divisor != 0);
        }

        [[nodiscard]] std::size_t checked_multiply(
            const std::size_t left,
            const std::size_t right,
            const char *name)
        {
            if (left != 0 && right > std::numeric_limits<std::size_t>::max() / left)
                throw std::overflow_error(std::string(name) + " overflow");
            return left * right;
        }
    }

    std::size_t KeywordDatabase::keyword_count() const noexcept { return keyword_count_; }
    std::size_t KeywordDatabase::document_count() const noexcept { return document_count_; }
    std::size_t KeywordDatabase::fragment_width() const noexcept { return fragment_width_; }
    std::size_t KeywordDatabase::fragment_count() const noexcept { return fragment_count_; }
    std::size_t KeywordDatabase::logical_storage_bytes() const noexcept
    {
        return logical_storage_bytes_;
    }

    bool KeywordDatabase::contains(
        const std::size_t keyword,
        const std::size_t document) const
    {
        if (keyword >= keyword_count_) throw std::out_of_range("keyword row is out of range");
        if (document >= document_count_) throw std::out_of_range("document is out of range");
        const auto word = row_major_words_[keyword * row_word_count_ + document / 64];
        return ((word >> (document % 64)) & 1U) != 0;
    }

    void KeywordDatabase::copy_fragment(
        const std::size_t keyword,
        const std::size_t fragment,
        const std::span<std::uint64_t> destination) const
    {
        if (keyword >= keyword_count_) throw std::out_of_range("keyword row is out of range");
        if (fragment >= fragment_count_) throw std::out_of_range("bitmap fragment is out of range");
        if (destination.size() != fragment_width_)
            throw std::invalid_argument("bitmap fragment destination has the wrong width");
        std::fill(destination.begin(), destination.end(), 0);
        const std::size_t begin = fragment * fragment_width_;
        const std::size_t end = std::min(begin + fragment_width_, document_count_);
        for (std::size_t document = begin; document < end; ++document)
            destination[document - begin] = static_cast<std::uint64_t>(contains(keyword, document));
    }

    KeywordDatabase build_keyword_database(
        const Dataset &dataset,
        const std::size_t fragment_width)
    {
        if (dataset.parameters.keyword_count == 0 || dataset.documents.empty())
            throw std::invalid_argument("keyword database requires nonempty dimensions");
        KeywordDatabase database;
        database.keyword_count_ = dataset.parameters.keyword_count;
        database.document_count_ = dataset.documents.size();
        database.fragment_width_ = fragment_width;
        database.fragment_count_ = ceil_divide(database.document_count_, fragment_width);
        database.row_word_count_ = ceil_divide(database.document_count_, 64);
        database.row_major_words_.assign(
            checked_multiply(
                database.keyword_count_, database.row_word_count_, "keyword bitmap words"),
            0);
        const auto logical_bits = checked_multiply(
            database.keyword_count_, database.document_count_, "logical bitmap bits");
        database.logical_storage_bytes_ = ceil_divide(logical_bits, 8);

        // A single O(Md) pass is asymptotically optimal because every keyword assignment
        // must be read. Packed row-major words keep the long-lived bitmap compact, while
        // fragment expansion is deferred to offline plaintext preprocessing.
        for (std::size_t document = 0; document < dataset.documents.size(); ++document)
        {
            const auto &entry = dataset.documents[document];
            if (entry.id != document)
                throw std::invalid_argument("document ids must equal stable positions");
            std::unordered_set<std::uint32_t> unique;
            for (const auto keyword : entry.keyword_ids)
            {
                if (keyword >= database.keyword_count_)
                    throw std::out_of_range("document keyword is outside keyword_count");
                if (!unique.insert(keyword).second)
                    throw std::invalid_argument("document contains duplicate keyword ids");
                database.row_major_words_[
                    static_cast<std::size_t>(keyword) * database.row_word_count_ + document / 64] |=
                    std::uint64_t{1} << (document % 64);
            }
        }
        return database;
    }
}
