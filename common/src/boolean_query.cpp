#include "pir/common/boolean_query.hpp"

#include <algorithm>
#include <stdexcept>
#include <unordered_set>

namespace pir::common
{
    struct BooleanQuery::Node
    {
        Kind kind;
        std::uint32_t keyword_id = 0;
        std::shared_ptr<const Node> left;
        std::shared_ptr<const Node> right;
    };

    namespace
    {
        [[nodiscard]] BooleanQuery push_not_impl(
            const BooleanQuery &query,
            const bool negated)
        {
            switch (query.kind())
            {
            case BooleanQuery::Kind::keyword:
                return negated
                           ? BooleanQuery::Not(BooleanQuery::Keyword(query.keyword_id()))
                           : BooleanQuery::Keyword(query.keyword_id());
            case BooleanQuery::Kind::logical_not:
                return push_not_impl(query.left(), !negated);
            case BooleanQuery::Kind::logical_and:
                return negated
                           ? BooleanQuery::Or(
                                 push_not_impl(query.left(), true),
                                 push_not_impl(query.right(), true))
                           : BooleanQuery::And(
                                 push_not_impl(query.left(), false),
                                 push_not_impl(query.right(), false));
            case BooleanQuery::Kind::logical_or:
                return negated
                           ? BooleanQuery::And(
                                 push_not_impl(query.left(), true),
                                 push_not_impl(query.right(), true))
                           : BooleanQuery::Or(
                                 push_not_impl(query.left(), false),
                                 push_not_impl(query.right(), false));
            }
            throw std::logic_error("unknown Boolean query kind");
        }

        void append_leaves(
            const BooleanQuery &query,
            std::vector<std::uint32_t> &output)
        {
            if (query.kind() == BooleanQuery::Kind::keyword)
            {
                output.push_back(query.keyword_id());
                return;
            }
            append_leaves(query.left(), output);
            if (query.kind() != BooleanQuery::Kind::logical_not)
                append_leaves(query.right(), output);
        }

        [[nodiscard]] bool evaluate_document(
            const BooleanQuery &query,
            const Document &document,
            const std::size_t keyword_count)
        {
            switch (query.kind())
            {
            case BooleanQuery::Kind::keyword:
                if (query.keyword_id() >= keyword_count)
                    throw std::out_of_range("query keyword is outside keyword_count");
                return std::binary_search(
                    document.keyword_ids.begin(),
                    document.keyword_ids.end(),
                    query.keyword_id());
            case BooleanQuery::Kind::logical_not:
                return !evaluate_document(query.left(), document, keyword_count);
            case BooleanQuery::Kind::logical_and:
                return evaluate_document(query.left(), document, keyword_count) &&
                       evaluate_document(query.right(), document, keyword_count);
            case BooleanQuery::Kind::logical_or:
                return evaluate_document(query.left(), document, keyword_count) ||
                       evaluate_document(query.right(), document, keyword_count);
            }
            throw std::logic_error("unknown Boolean query kind");
        }
    }

    BooleanQuery::BooleanQuery(std::shared_ptr<const Node> node)
        : node_(std::move(node))
    {
        if (!node_) throw std::invalid_argument("Boolean query node must not be null");
    }

    BooleanQuery BooleanQuery::Keyword(const std::uint32_t keyword_id)
    {
        return BooleanQuery(std::make_shared<Node>(Node{Kind::keyword, keyword_id, {}, {}}));
    }

    BooleanQuery BooleanQuery::Not(BooleanQuery operand)
    {
        return BooleanQuery(std::make_shared<Node>(Node{
            Kind::logical_not, 0, std::move(operand.node_), {}}));
    }

    BooleanQuery BooleanQuery::And(BooleanQuery left, BooleanQuery right)
    {
        return BooleanQuery(std::make_shared<Node>(Node{
            Kind::logical_and, 0, std::move(left.node_), std::move(right.node_)}));
    }

    BooleanQuery BooleanQuery::Or(BooleanQuery left, BooleanQuery right)
    {
        return BooleanQuery(std::make_shared<Node>(Node{
            Kind::logical_or, 0, std::move(left.node_), std::move(right.node_)}));
    }

    BooleanQuery::Kind BooleanQuery::kind() const noexcept
    {
        return node_->kind;
    }

    std::uint32_t BooleanQuery::keyword_id() const
    {
        if (kind() != Kind::keyword)
            throw std::logic_error("Boolean query node is not a keyword");
        return node_->keyword_id;
    }

    BooleanQuery BooleanQuery::left() const
    {
        if (!node_->left) throw std::logic_error("Boolean query node has no left operand");
        return BooleanQuery(node_->left);
    }

    BooleanQuery BooleanQuery::right() const
    {
        if (!node_->right) throw std::logic_error("Boolean query node has no right operand");
        return BooleanQuery(node_->right);
    }

    std::vector<std::uint32_t> leaf_keywords(const BooleanQuery &query)
    {
        std::vector<std::uint32_t> result;
        append_leaves(query, result);
        return result;
    }

    std::vector<std::uint32_t> distinct_leaf_keywords(const BooleanQuery &query)
    {
        std::vector<std::uint32_t> result;
        std::unordered_set<std::uint32_t> seen;
        for (const auto keyword : leaf_keywords(query))
            if (seen.insert(keyword).second) result.push_back(keyword);
        return result;
    }

    BooleanQuery push_not_to_leaves(const BooleanQuery &query)
    {
        return push_not_impl(query, false);
    }

    bool is_negation_normal_form(const BooleanQuery &query)
    {
        switch (query.kind())
        {
        case BooleanQuery::Kind::keyword:
            return true;
        case BooleanQuery::Kind::logical_not:
            return query.left().kind() == BooleanQuery::Kind::keyword;
        case BooleanQuery::Kind::logical_and:
        case BooleanQuery::Kind::logical_or:
            return is_negation_normal_form(query.left()) &&
                   is_negation_normal_form(query.right());
        }
        return false;
    }

    std::vector<std::uint8_t> evaluate_query(
        const BooleanQuery &query,
        const Dataset &dataset)
    {
        std::vector<std::uint8_t> result(dataset.documents.size(), 0);
        for (std::size_t index = 0; index < dataset.documents.size(); ++index)
        {
            // Evaluate one document at a time to keep auxiliary storage O(tree depth)
            // instead of retaining an M-bit temporary for every AST node.
            result[index] = static_cast<std::uint8_t>(evaluate_document(
                query, dataset.documents[index], dataset.parameters.keyword_count));
        }
        return result;
    }
}
