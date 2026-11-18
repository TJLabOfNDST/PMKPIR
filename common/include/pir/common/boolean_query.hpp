#pragma once

#include "pir/common/dataset.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace pir::common
{
    class BooleanQuery
    {
    public:
        enum class Kind
        {
            keyword,
            logical_not,
            logical_and,
            logical_or
        };

        [[nodiscard]] static BooleanQuery Keyword(std::uint32_t keyword_id);
        [[nodiscard]] static BooleanQuery Not(BooleanQuery operand);
        [[nodiscard]] static BooleanQuery And(BooleanQuery left, BooleanQuery right);
        [[nodiscard]] static BooleanQuery Or(BooleanQuery left, BooleanQuery right);

        [[nodiscard]] Kind kind() const noexcept;
        [[nodiscard]] std::uint32_t keyword_id() const;
        [[nodiscard]] BooleanQuery left() const;
        [[nodiscard]] BooleanQuery right() const;

    private:
        struct Node;
        explicit BooleanQuery(std::shared_ptr<const Node> node);
        std::shared_ptr<const Node> node_;
    };

    [[nodiscard]] std::vector<std::uint32_t> leaf_keywords(
        const BooleanQuery &query);
    [[nodiscard]] std::vector<std::uint32_t> distinct_leaf_keywords(
        const BooleanQuery &query);
    [[nodiscard]] BooleanQuery push_not_to_leaves(const BooleanQuery &query);
    [[nodiscard]] bool is_negation_normal_form(const BooleanQuery &query);
    [[nodiscard]] std::vector<std::uint8_t> evaluate_query(
        const BooleanQuery &query,
        const Dataset &dataset);
}
