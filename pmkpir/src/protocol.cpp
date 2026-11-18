#include "pir/pmkpir/protocol.hpp"

#include "pir/common/bfv.hpp"
#include "pir/common/constant_weight.hpp"
#include "pir/common/keyword_database.hpp"
#include "pir/common/persistence.hpp"
#include "pir/pmkpir/layout.hpp"
#include "pir/pmkpir/wide_keyword_codebook.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_set>

namespace pir::pmkpir
{
    namespace
    {
        [[nodiscard]] std::size_t ceil_divide(
            const std::size_t value,
            const std::size_t divisor)
        {
            if (divisor == 0) throw std::invalid_argument("division by zero");
            return value / divisor + static_cast<std::size_t>(value % divisor != 0);
        }

        [[nodiscard]] std::size_t serialized_size(const seal::Ciphertext &ciphertext)
        {
            std::ostringstream stream(std::ios::binary);
            const auto bytes = ciphertext.save(stream, seal::compr_mode_type::none);
            if (bytes < 0) throw std::runtime_error("negative ciphertext serialization size");
            return static_cast<std::size_t>(bytes);
        }

        [[nodiscard]] std::size_t checked_add(
            const std::size_t left,
            const std::size_t right)
        {
            if (right > std::numeric_limits<std::size_t>::max() - left)
                throw std::overflow_error("ciphertext serialization size overflow");
            return left + right;
        }

        [[nodiscard]] std::uint64_t multiply_mod(
            const std::uint64_t left,
            const std::uint64_t right,
            const std::uint64_t modulus) noexcept
        {
            return (left * right) % modulus;
        }

        [[nodiscard]] std::uint64_t inverse_mod(
            std::uint64_t value,
            const std::uint64_t modulus) noexcept
        {
            std::uint64_t result = 1;
            std::uint64_t exponent = modulus - 2;
            while (exponent != 0)
            {
                if ((exponent & 1U) != 0) result = multiply_mod(result, value, modulus);
                value = multiply_mod(value, value, modulus);
                exponent >>= 1U;
            }
            return result;
        }

        [[nodiscard]] std::uint64_t factorial_mod(
            const std::size_t value,
            const std::uint64_t modulus) noexcept
        {
            std::uint64_t result = 1;
            for (std::size_t factor = 2; factor <= value; ++factor)
                result = multiply_mod(result, factor % modulus, modulus);
            return result;
        }

        [[nodiscard]] std::vector<int> required_rotation_steps(
            const InterleavedLayout &layout)
        {
            std::vector<int> steps = layout.reduction_rotation_steps();
            for (std::size_t distance = 1; distance < layout.blocks_per_row(); ++distance)
            {
                steps.push_back(static_cast<int>(distance));
                steps.push_back(-static_cast<int>(distance));
            }
            return steps;
        }

        [[nodiscard]] bool is_power_of_two(const std::size_t value) noexcept
        {
            return value != 0 && (value & (value - 1)) == 0;
        }
    }

    std::size_t PreprocessedDatabase::keyword_count() const noexcept { return keyword_count_; }
    std::size_t PreprocessedDatabase::document_count() const noexcept { return document_count_; }
    std::size_t PreprocessedDatabase::fragment_count() const noexcept { return fragment_count_; }
    const SetupMetrics &PreprocessedDatabase::setup_metrics() const noexcept
    {
        return setup_metrics_;
    }

    class Client::Impl
    {
    public:
        Impl(pir::common::BfvParameters parameters, const std::size_t public_domain_bits)
            : parameters_(std::move(parameters)),
              public_domain_bits_(public_domain_bits),
              layout_(parameters_.polynomial_modulus_degree, parameters_.block_count),
              context_(pir::common::make_bfv_context(parameters_, public_domain_bits_))
        {
            seal::KeyGenerator key_generator(*context_);
            secret_key_ = key_generator.secret_key();
            key_generator.create_public_key(public_key_);
            key_generator.create_relin_keys(relinearization_keys_);
            const auto steps = required_rotation_steps(layout_);
            const auto elements = pir::common::galois_elements_for_steps(
                parameters_.polynomial_modulus_degree, steps, true);
            key_generator.create_galois_keys(elements, galois_keys_);
            encoder_ = std::make_unique<seal::BatchEncoder>(*context_);
            encryptor_ = std::make_unique<seal::Encryptor>(*context_, public_key_);
            decryptor_ = std::make_unique<seal::Decryptor>(*context_, secret_key_);
        }

        [[nodiscard]] EncryptedQuery create_query(const CompiledQuery &compiled) const
        {
            if (!compiled.root || compiled.packed_keywords.empty())
                throw std::invalid_argument("compiled PMKPIR query is empty");
            if (compiled.block_count != parameters_.block_count)
                throw std::invalid_argument("compiled PMKPIR block_count differs from BFV parameters");
            EncryptedQuery result{{}, compiled, 0};
            const std::size_t container_count = ceil_divide(
                compiled.packed_keywords.size(), parameters_.block_count);
            result.ciphertexts.reserve(container_count);
            const std::uint64_t domain_limit = public_domain_bits_ >= 32
                                                   ? std::uint64_t{1} << 32U
                                                   : std::uint64_t{1} << public_domain_bits_;
            for (std::size_t container = 0; container < container_count; ++container)
            {
                std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
                for (std::size_t block = 0; block < parameters_.block_count; ++block)
                {
                    const std::size_t source = container * parameters_.block_count + block;
                    if (source >= compiled.packed_keywords.size()) break;
                    const auto keyword = compiled.packed_keywords[source];
                    if (keyword >= domain_limit)
                        throw std::out_of_range("query keyword exceeds the public domain");
                    for (const auto position : pir::common::unrank_constant_weight_u64(
                             layout_.region_width(), parameters_.constant_weight, keyword))
                    {
                        slots[layout_.slot_index(block, position)] = 1;
                    }
                }
                seal::Plaintext plaintext;
                encoder_->encode(slots, plaintext);
                seal::Ciphertext ciphertext;
                encryptor_->encrypt(plaintext, ciphertext);
                const auto serialization_begin = std::chrono::steady_clock::now();
                result.serialized_size_bytes = checked_add(
                    result.serialized_size_bytes, serialized_size(ciphertext));
                result.serialization_ms += std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - serialization_begin).count();
                result.ciphertexts.push_back(std::move(ciphertext));
            }
            return result;
        }

        [[nodiscard]] EncryptedQuery create_query(
            const CompiledQuery &compiled,
            const WideKeywordCodebook &codebook) const
        {
            // This explicit path isolates wide identifiers from the existing uint64 benchmark path.
            if (!compiled.root || compiled.packed_keywords.empty())
                throw std::invalid_argument("compiled PMKPIR query is empty");
            if (compiled.block_count != parameters_.block_count)
                throw std::invalid_argument("compiled PMKPIR block_count differs from BFV parameters");
            if (codebook.domain_bits() != public_domain_bits_)
                throw std::invalid_argument("wide codebook domain differs from the PMKPIR client");
            if (codebook.code_width() != layout_.region_width())
                throw std::invalid_argument("wide codebook width differs from the PMKPIR layout");
            if (codebook.weight() != parameters_.constant_weight)
                throw std::invalid_argument("wide codebook weight differs from the PMKPIR parameters");

            EncryptedQuery result{{}, compiled, 0};
            const std::size_t container_count = ceil_divide(
                compiled.packed_keywords.size(), parameters_.block_count);
            result.ciphertexts.reserve(container_count);
            for (std::size_t container = 0; container < container_count; ++container)
            {
                std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
                for (std::size_t block = 0; block < parameters_.block_count; ++block)
                {
                    const std::size_t source = container * parameters_.block_count + block;
                    if (source >= compiled.packed_keywords.size()) break;
                    for (const auto position : codebook.positions(
                             compiled.packed_keywords[source]))
                    {
                        slots[layout_.slot_index(block, position)] = 1;
                    }
                }
                seal::Plaintext plaintext;
                encoder_->encode(slots, plaintext);
                seal::Ciphertext ciphertext;
                encryptor_->encrypt(plaintext, ciphertext);
                const auto serialization_begin = std::chrono::steady_clock::now();
                result.serialized_size_bytes = checked_add(
                    result.serialized_size_bytes, serialized_size(ciphertext));
                result.serialization_ms += std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - serialization_begin).count();
                result.ciphertexts.push_back(std::move(ciphertext));
            }
            return result;
        }

        [[nodiscard]] DecryptedSelection decrypt_selection(
            const EncryptedSelection &selection,
            const std::size_t document_count) const
        {
            const bool packed_fragments = document_count > layout_.region_width();
            const std::size_t documents_per_ciphertext = packed_fragments
                                                             ? parameters_.polynomial_modulus_degree
                                                             : layout_.region_width();
            const std::size_t expected = ceil_divide(document_count, documents_per_ciphertext);
            if (selection.fragments.size() != expected)
                throw std::invalid_argument("PMKPIR response fragment count mismatch");
            DecryptedSelection result;
            result.bitmap.reserve(document_count);
            result.minimum_noise_budget_bits = std::numeric_limits<int>::max();
            for (const auto &ciphertext : selection.fragments)
            {
                const int noise = decryptor_->invariant_noise_budget(ciphertext);
                if (noise <= 0) throw std::runtime_error("PMKPIR response noise is exhausted");
                result.minimum_noise_budget_bits = std::min(
                    result.minimum_noise_budget_bits, noise);
                seal::Plaintext plaintext;
                decryptor_->decrypt(ciphertext, plaintext);
                std::vector<std::uint64_t> slots;
                encoder_->decode(plaintext, slots);
                const std::size_t decoded_blocks = packed_fragments
                                                       ? parameters_.block_count
                                                       : 1;
                for (std::size_t block = 0;
                     block < decoded_blocks && result.bitmap.size() < document_count;
                     ++block)
                {
                    const std::size_t remaining = document_count - result.bitmap.size();
                    const std::size_t count = std::min(remaining, layout_.region_width());
                    for (std::size_t index = 0; index < count; ++index)
                    {
                        const auto value = slots[layout_.slot_index(block, index)];
                        if (value > 1)
                            throw std::runtime_error("PMKPIR selection slot is not Boolean");
                        result.bitmap.push_back(static_cast<std::uint8_t>(value));
                    }
                }
            }
            return result;
        }

        pir::common::BfvParameters parameters_;
        std::size_t public_domain_bits_;
        InterleavedLayout layout_;
        std::shared_ptr<seal::SEALContext> context_;
        seal::SecretKey secret_key_;
        seal::PublicKey public_key_;
        seal::RelinKeys relinearization_keys_;
        seal::GaloisKeys galois_keys_;
        std::unique_ptr<seal::BatchEncoder> encoder_;
        std::unique_ptr<seal::Encryptor> encryptor_;
        std::unique_ptr<seal::Decryptor> decryptor_;
    };

    Client::Client(pir::common::BfvParameters parameters, const std::size_t public_domain_bits)
        : impl_(std::make_unique<Impl>(std::move(parameters), public_domain_bits)) {}
    Client::~Client() = default;
    Client::Client(Client &&) noexcept = default;
    Client &Client::operator=(Client &&) noexcept = default;
    std::shared_ptr<seal::SEALContext> Client::context() const noexcept { return impl_->context_; }
    const seal::RelinKeys &Client::relinearization_keys() const noexcept
    {
        return impl_->relinearization_keys_;
    }
    const seal::GaloisKeys &Client::galois_keys() const noexcept { return impl_->galois_keys_; }
    EncryptedQuery Client::create_query(const CompiledQuery &compiled) const
    {
        return impl_->create_query(compiled);
    }
    EncryptedQuery Client::create_query(
        const CompiledQuery &compiled,
        const WideKeywordCodebook &codebook) const
    {
        return impl_->create_query(compiled, codebook);
    }
    DecryptedSelection Client::decrypt_selection(
        const EncryptedSelection &selection,
        const std::size_t document_count) const
    {
        return impl_->decrypt_selection(selection, document_count);
    }

    class BooleanEvaluator
    {
    public:
        BooleanEvaluator(
            const pir::common::BfvParameters &parameters,
            const InterleavedLayout &layout,
            const std::vector<std::vector<seal::Ciphertext>> &scan_results,
            const std::size_t fragment,
            seal::BatchEncoder &encoder,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relinearization_keys,
            const seal::GaloisKeys &galois_keys,
            pir::common::HomomorphicCounters &counters)
            : parameters_(parameters),
              layout_(layout),
              scan_results_(scan_results),
              fragment_(fragment),
              encoder_(encoder),
              evaluator_(evaluator),
              relinearization_keys_(relinearization_keys),
              galois_keys_(galois_keys),
              counters_(counters)
        {
        }

        [[nodiscard]] seal::Ciphertext evaluate(const std::shared_ptr<const PlanNode> &node)
        {
            if (!node) throw std::invalid_argument("PMKPIR Boolean plan node is null");
            switch (node->kind)
            {
            case PlanKind::literal:
                return route_literal(node->literal, 0);
            case PlanKind::local_dnf:
                return evaluate_local_dnf(*node);
            case PlanKind::logical_and:
            case PlanKind::logical_or:
                return evaluate_gate(*node);
            }
            throw std::logic_error("unknown PMKPIR Boolean plan kind");
        }

    private:
        [[nodiscard]] const seal::Plaintext &block_mask(const std::size_t block)
        {
            if (const auto found = block_masks_.find(block); found != block_masks_.end())
                return found->second;
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            for (std::size_t offset = 0; offset < layout_.region_width(); ++offset)
                slots[layout_.slot_index(block, offset)] = 1;
            seal::Plaintext plaintext;
            encoder_.encode(slots, plaintext);
            return block_masks_.emplace(block, std::move(plaintext)).first->second;
        }

        [[nodiscard]] seal::Ciphertext route_positive(
            const std::size_t source_index,
            const std::size_t target_block)
        {
            const std::size_t container = source_index / parameters_.block_count;
            const std::size_t source_block = source_index % parameters_.block_count;
            const auto key = std::make_tuple(container, source_block, target_block);
            if (const auto found = route_cache_.find(key); found != route_cache_.end())
                return found->second;
            if (container >= scan_results_.size() ||
                fragment_ >= scan_results_[container].size() ||
                target_block >= parameters_.block_count)
            {
                throw std::out_of_range("PMKPIR Boolean route is out of range");
            }
            seal::Ciphertext routed;
            evaluator_.multiply_plain(
                scan_results_[container][fragment_], block_mask(source_block), routed);
            ++counters_.plaintext_multiplications;
            const std::size_t source_row = source_block / layout_.blocks_per_row();
            const std::size_t target_row = target_block / layout_.blocks_per_row();
            if (source_row != target_row)
            {
                evaluator_.rotate_columns_inplace(routed, galois_keys_);
                ++counters_.row_swaps;
            }
            const std::size_t source_column = source_block % layout_.blocks_per_row();
            const std::size_t target_column = target_block % layout_.blocks_per_row();
            const std::size_t row_size = parameters_.polynomial_modulus_degree / 2;
            const std::size_t delta = (source_column + row_size - target_column) % row_size;
            if (delta != 0)
            {
                const int signed_delta = delta <= row_size / 2
                                             ? static_cast<int>(delta)
                                             : -static_cast<int>(row_size - delta);
                evaluator_.rotate_rows_inplace(routed, signed_delta, galois_keys_);
                ++counters_.row_rotations;
            }
            // One cached ciphertext per source/target route trades bounded O(zB) memory
            // for avoiding repeated masks and key switches when literals repeat.
            route_cache_.emplace(key, routed);
            return routed;
        }

        [[nodiscard]] seal::Ciphertext route_literal(
            const Literal &literal,
            const std::size_t target_block)
        {
            auto result = route_positive(literal.source_index, target_block);
            if (literal.negated)
            {
                evaluator_.negate_inplace(result);
                evaluator_.add_plain_inplace(result, block_mask(target_block));
            }
            return result;
        }

        [[nodiscard]] seal::Ciphertext pair_shift(
            const seal::Ciphertext &input,
            const std::size_t distance)
        {
            seal::Ciphertext shifted;
            if (distance < layout_.blocks_per_row())
            {
                evaluator_.rotate_rows(
                    input, static_cast<int>(distance), galois_keys_, shifted);
                ++counters_.row_rotations;
            }
            else if (distance == layout_.blocks_per_row())
            {
                evaluator_.rotate_columns(input, galois_keys_, shifted);
                ++counters_.row_swaps;
            }
            else
            {
                throw std::logic_error("PMKPIR pair shift exceeds the two-row workspace");
            }
            return shifted;
        }

        [[nodiscard]] seal::Ciphertext evaluate_local_dnf(const PlanNode &node)
        {
            if (node.dnf_clauses.empty() ||
                !is_power_of_two(node.padded_clause_length) ||
                !is_power_of_two(node.padded_clause_count) ||
                node.padded_clause_length * node.padded_clause_count >
                    parameters_.block_count)
            {
                throw std::invalid_argument("local DNF exceeds the PMKPIR block workspace");
            }
            bool initialized = false;
            seal::Ciphertext work;
            std::vector<std::uint64_t> bias(parameters_.polynomial_modulus_degree, 0);
            for (std::size_t clause = 0; clause < node.padded_clause_count; ++clause)
            {
                const bool real_clause = clause < node.dnf_clauses.size();
                const std::size_t literal_count = real_clause
                                                      ? node.dnf_clauses[clause].size()
                                                      : 0;
                for (std::size_t position = 0;
                     position < node.padded_clause_length;
                     ++position)
                {
                    const std::size_t target = clause * node.padded_clause_length + position;
                    if (real_clause && position < literal_count)
                    {
                        auto routed = route_literal(node.dnf_clauses[clause][position], target);
                        if (!initialized)
                        {
                            work = std::move(routed);
                            initialized = true;
                        }
                        else
                        {
                            evaluator_.add_inplace(work, routed);
                            ++counters_.additions;
                        }
                    }
                    else if (real_clause || position != 0)
                    {
                        for (std::size_t offset = 0; offset < layout_.region_width(); ++offset)
                            bias[layout_.slot_index(target, offset)] = 1;
                    }
                }
            }
            if (!initialized) throw std::logic_error("local DNF has no real literal");
            if (std::any_of(bias.begin(), bias.end(), [](const auto value) { return value != 0; }))
            {
                seal::Plaintext bias_plaintext;
                encoder_.encode(bias, bias_plaintext);
                evaluator_.add_plain_inplace(work, bias_plaintext);
            }
            for (std::size_t distance = 1;
                 distance < node.padded_clause_length;
                 distance <<= 1U)
            {
                auto shifted = pair_shift(work, distance);
                evaluator_.multiply_inplace(work, shifted);
                evaluator_.relinearize_inplace(work, relinearization_keys_);
                ++counters_.ciphertext_multiplications;
                ++counters_.relinearizations;
            }
            const std::size_t workspace =
                node.padded_clause_length * node.padded_clause_count;
            for (std::size_t distance = node.padded_clause_length;
                 distance < workspace;
                 distance <<= 1U)
            {
                auto shifted = pair_shift(work, distance);
                seal::Ciphertext product;
                evaluator_.multiply(work, shifted, product);
                evaluator_.relinearize_inplace(product, relinearization_keys_);
                evaluator_.add_inplace(work, shifted);
                evaluator_.sub_inplace(work, product);
                ++counters_.ciphertext_multiplications;
                ++counters_.relinearizations;
                counters_.additions += 2;
            }
            return work;
        }

        [[nodiscard]] seal::Ciphertext evaluate_gate(const PlanNode &node)
        {
            if (node.children.size() != 2)
                throw std::invalid_argument("fallback Boolean gate must have two children");
            auto left = evaluate(node.children[0]);
            auto right = evaluate(node.children[1]);
            if (node.kind == PlanKind::logical_and)
            {
                evaluator_.multiply_inplace(left, right);
                evaluator_.relinearize_inplace(left, relinearization_keys_);
                ++counters_.ciphertext_multiplications;
                ++counters_.relinearizations;
                return left;
            }
            seal::Ciphertext product;
            evaluator_.multiply(left, right, product);
            evaluator_.relinearize_inplace(product, relinearization_keys_);
            evaluator_.add_inplace(left, right);
            evaluator_.sub_inplace(left, product);
            ++counters_.ciphertext_multiplications;
            ++counters_.relinearizations;
            counters_.additions += 2;
            return left;
        }

        const pir::common::BfvParameters &parameters_;
        const InterleavedLayout &layout_;
        const std::vector<std::vector<seal::Ciphertext>> &scan_results_;
        std::size_t fragment_;
        seal::BatchEncoder &encoder_;
        seal::Evaluator &evaluator_;
        const seal::RelinKeys &relinearization_keys_;
        const seal::GaloisKeys &galois_keys_;
        pir::common::HomomorphicCounters &counters_;
        std::map<std::size_t, seal::Plaintext> block_masks_;
        std::map<std::tuple<std::size_t, std::size_t, std::size_t>, seal::Ciphertext>
            route_cache_;
    };

    class PackedFragmentBooleanEvaluator
    {
    public:
        PackedFragmentBooleanEvaluator(
            const pir::common::BfvParameters &parameters,
            const InterleavedLayout &layout,
            const std::vector<std::vector<seal::Ciphertext>> &scan_results,
            const std::size_t fragment_begin,
            const std::size_t fragment_end,
            const std::size_t packed_keyword_count,
            seal::BatchEncoder &encoder,
            seal::Evaluator &evaluator,
            const seal::RelinKeys &relinearization_keys,
            const seal::GaloisKeys &galois_keys,
            pir::common::HomomorphicCounters &counters)
            : parameters_(parameters),
              layout_(layout),
              scan_results_(scan_results),
              fragment_begin_(fragment_begin),
              fragment_end_(fragment_end),
              packed_keyword_count_(packed_keyword_count),
              encoder_(encoder),
              evaluator_(evaluator),
              relinearization_keys_(relinearization_keys),
              galois_keys_(galois_keys),
              counters_(counters)
        {
            const std::size_t fragment_count = fragment_end_ - fragment_begin_;
            if (fragment_begin_ >= fragment_end_ ||
                fragment_count > parameters_.block_count)
            {
                throw std::invalid_argument("invalid PMKPIR packed fragment group");
            }
            if (packed_keyword_count_ == 0 ||
                ceil_divide(packed_keyword_count_, parameters_.block_count) !=
                    scan_results_.size())
            {
                throw std::invalid_argument("invalid PMKPIR packed keyword count");
            }
        }

        [[nodiscard]] seal::Ciphertext evaluate(const std::shared_ptr<const PlanNode> &node)
        {
            if (!node) throw std::invalid_argument("PMKPIR Boolean plan node is null");
            switch (node->kind)
            {
            case PlanKind::literal:
                return literal_value(node->literal);
            case PlanKind::local_dnf:
                return evaluate_local_dnf(*node);
            case PlanKind::logical_and:
            case PlanKind::logical_or:
                return evaluate_gate(*node);
            }
            throw std::logic_error("unknown PMKPIR Boolean plan kind");
        }

    private:
        [[nodiscard]] const seal::Plaintext &block_mask(const std::size_t block)
        {
            if (block >= parameters_.block_count)
                throw std::out_of_range("PMKPIR packed block mask is out of range");
            if (const auto found = block_masks_.find(block); found != block_masks_.end())
                return found->second;
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            for (std::size_t offset = 0; offset < layout_.region_width(); ++offset)
                slots[layout_.slot_index(block, offset)] = 1;
            seal::Plaintext plaintext;
            encoder_.encode(slots, plaintext);
            return block_masks_.emplace(block, std::move(plaintext)).first->second;
        }

        [[nodiscard]] const seal::Plaintext &active_blocks_mask()
        {
            if (active_blocks_mask_ready_) return active_blocks_mask_;
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            const std::size_t active_blocks = fragment_end_ - fragment_begin_;
            for (std::size_t block = 0; block < active_blocks; ++block)
                for (std::size_t offset = 0; offset < layout_.region_width(); ++offset)
                    slots[layout_.slot_index(block, offset)] = 1;
            encoder_.encode(slots, active_blocks_mask_);
            active_blocks_mask_ready_ = true;
            return active_blocks_mask_;
        }

        [[nodiscard]] const seal::Plaintext &transpose_mask(const std::size_t stride)
        {
            if (!is_power_of_two(stride) || stride > layout_.blocks_per_row())
                throw std::invalid_argument("invalid PMKPIR butterfly stride");
            if (const auto found = transpose_masks_.find(stride);
                found != transpose_masks_.end())
            {
                return found->second;
            }
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            for (std::size_t block = 0; block < parameters_.block_count; ++block)
            {
                if ((block & stride) != 0) continue;
                for (std::size_t offset = 0; offset < layout_.region_width(); ++offset)
                    slots[layout_.slot_index(block, offset)] = 1;
            }
            seal::Plaintext plaintext;
            encoder_.encode(slots, plaintext);
            return transpose_masks_.emplace(stride, std::move(plaintext)).first->second;
        }

        void shift_block_group_inplace(
            seal::Ciphertext &ciphertext,
            const std::size_t stride,
            const bool toward_higher_blocks)
        {
            if (!is_power_of_two(stride) || stride > layout_.blocks_per_row())
                throw std::invalid_argument("invalid PMKPIR butterfly shift");
            if (stride == layout_.blocks_per_row())
            {
                evaluator_.rotate_columns_inplace(ciphertext, galois_keys_);
                ++counters_.row_swaps;
                return;
            }
            const int step = toward_higher_blocks
                                 ? -static_cast<int>(stride)
                                 : static_cast<int>(stride);
            evaluator_.rotate_rows_inplace(ciphertext, step, galois_keys_);
            ++counters_.row_rotations;
        }

        [[nodiscard]] const std::vector<seal::Ciphertext> &transposed_container(
            const std::size_t container)
        {
            if (const auto found = transposed_container_cache_.find(container);
                found != transposed_container_cache_.end())
            {
                return found->second;
            }
            const std::size_t block_count = parameters_.block_count;
            if (container >= scan_results_.size() ||
                fragment_end_ - fragment_begin_ != block_count ||
                (container + 1) * block_count > packed_keyword_count_ ||
                fragment_end_ > scan_results_[container].size())
            {
                throw std::out_of_range("PMKPIR butterfly container is incomplete");
            }

            std::vector<seal::Ciphertext> values;
            values.reserve(block_count);
            for (std::size_t fragment = fragment_begin_; fragment < fragment_end_; ++fragment)
                values.push_back(scan_results_[container][fragment]);

            // The butterfly exchanges one ciphertext-index bit with one block-index bit
            // per stage. It keeps O(B) ciphertexts and reduces masks/key switches from
            // O(B^2) to O(B log B), a bounded space-for-time tradeoff.
            for (std::size_t stride = 1; stride < block_count; stride <<= 1U)
            {
                const auto &low_blocks = transpose_mask(stride);
                for (std::size_t base = 0; base < block_count; base += stride * 2)
                {
                    for (std::size_t offset = 0; offset < stride; ++offset)
                    {
                        const std::size_t low_index = base + offset;
                        const std::size_t high_index = low_index + stride;
                        seal::Ciphertext low_selected;
                        seal::Ciphertext high_selected;
                        evaluator_.multiply_plain(
                            values[low_index], low_blocks, low_selected);
                        evaluator_.multiply_plain(
                            values[high_index], low_blocks, high_selected);
                        counters_.plaintext_multiplications += 2;

                        seal::Ciphertext low_complement = values[low_index];
                        seal::Ciphertext high_complement = values[high_index];
                        evaluator_.sub_inplace(low_complement, low_selected);
                        evaluator_.sub_inplace(high_complement, high_selected);
                        counters_.additions += 2;

                        shift_block_group_inplace(
                            high_selected, stride, true);
                        shift_block_group_inplace(
                            low_complement, stride, false);
                        evaluator_.add_inplace(low_selected, high_selected);
                        evaluator_.add_inplace(low_complement, high_complement);
                        counters_.additions += 2;

                        values[low_index] = std::move(low_selected);
                        values[high_index] = std::move(low_complement);
                    }
                }
            }
            return transposed_container_cache_.emplace(
                container, std::move(values)).first->second;
        }

        void route_block_inplace(
            seal::Ciphertext &ciphertext,
            const std::size_t source_block,
            const std::size_t target_block)
        {
            const std::size_t source_row = source_block / layout_.blocks_per_row();
            const std::size_t target_row = target_block / layout_.blocks_per_row();
            if (source_row != target_row)
            {
                evaluator_.rotate_columns_inplace(ciphertext, galois_keys_);
                ++counters_.row_swaps;
            }
            const std::size_t source_column = source_block % layout_.blocks_per_row();
            const std::size_t target_column = target_block % layout_.blocks_per_row();
            const std::size_t row_size = parameters_.polynomial_modulus_degree / 2;
            const std::size_t delta = (source_column + row_size - target_column) % row_size;
            if (delta == 0) return;
            const int signed_delta = delta <= row_size / 2
                                         ? static_cast<int>(delta)
                                         : -static_cast<int>(row_size - delta);
            evaluator_.rotate_rows_inplace(ciphertext, signed_delta, galois_keys_);
            ++counters_.row_rotations;
        }

        [[nodiscard]] seal::Ciphertext packed_positive(const std::size_t source_index)
        {
            if (source_index >= packed_keyword_count_)
                throw std::out_of_range("PMKPIR packed source index is out of range");
            if (const auto found = packed_leaf_cache_.find(source_index);
                found != packed_leaf_cache_.end())
            {
                return found->second;
            }
            const std::size_t container = source_index / parameters_.block_count;
            const std::size_t source_block = source_index % parameters_.block_count;
            if (container >= scan_results_.size() ||
                fragment_end_ > scan_results_[container].size())
            {
                throw std::out_of_range("PMKPIR packed Boolean source is out of range");
            }
            const bool full_fragment_group =
                fragment_end_ - fragment_begin_ == parameters_.block_count;
            const bool full_query_container =
                (container + 1) * parameters_.block_count <= packed_keyword_count_;
            if (full_fragment_group && full_query_container)
                return transposed_container(container)[source_block];

            bool initialized = false;
            seal::Ciphertext packed;
            for (std::size_t fragment = fragment_begin_; fragment < fragment_end_; ++fragment)
            {
                seal::Ciphertext routed;
                evaluator_.multiply_plain(
                    scan_results_[container][fragment], block_mask(source_block), routed);
                ++counters_.plaintext_multiplications;
                route_block_inplace(routed, source_block, fragment - fragment_begin_);
                if (!initialized)
                {
                    packed = std::move(routed);
                    initialized = true;
                }
                else
                {
                    evaluator_.add_inplace(packed, routed);
                    ++counters_.additions;
                }
            }
            if (!initialized) throw std::logic_error("PMKPIR packed leaf is empty");

            // Caching each positive leaf uses O(s) ciphertexts per output group, but avoids
            // repeating O(B) masks and key switches when the public plan reuses a keyword.
            packed_leaf_cache_.emplace(source_index, packed);
            return packed;
        }

        [[nodiscard]] seal::Ciphertext literal_value(const Literal &literal)
        {
            auto result = packed_positive(literal.source_index);
            if (literal.negated)
            {
                evaluator_.negate_inplace(result);
                evaluator_.add_plain_inplace(result, active_blocks_mask());
            }
            return result;
        }

        [[nodiscard]] seal::Ciphertext combine(
            seal::Ciphertext left,
            const seal::Ciphertext &right,
            const PlanKind kind)
        {
            if (kind == PlanKind::logical_and)
            {
                evaluator_.multiply_inplace(left, right);
                evaluator_.relinearize_inplace(left, relinearization_keys_);
                ++counters_.ciphertext_multiplications;
                ++counters_.relinearizations;
                return left;
            }
            if (kind != PlanKind::logical_or)
                throw std::invalid_argument("PMKPIR packed reducer requires AND or OR");
            seal::Ciphertext product;
            evaluator_.multiply(left, right, product);
            evaluator_.relinearize_inplace(product, relinearization_keys_);
            evaluator_.add_inplace(left, right);
            evaluator_.sub_inplace(left, product);
            ++counters_.ciphertext_multiplications;
            ++counters_.relinearizations;
            counters_.additions += 2;
            return left;
        }

        [[nodiscard]] seal::Ciphertext reduce_balanced(
            std::vector<seal::Ciphertext> values,
            const PlanKind kind)
        {
            if (values.empty()) throw std::invalid_argument("PMKPIR Boolean reduction is empty");
            // A balanced tree is work-optimal at O(q) operations and minimizes depth to
            // O(log q), preserving more noise budget than a left-deep evaluation.
            while (values.size() > 1)
            {
                std::vector<seal::Ciphertext> next;
                next.reserve((values.size() + 1) / 2);
                for (std::size_t index = 0; index < values.size(); index += 2)
                {
                    if (index + 1 == values.size())
                        next.push_back(std::move(values[index]));
                    else
                        next.push_back(combine(
                            std::move(values[index]), values[index + 1], kind));
                }
                values = std::move(next);
            }
            return std::move(values.front());
        }

        [[nodiscard]] seal::Ciphertext evaluate_local_dnf(const PlanNode &node)
        {
            if (node.dnf_clauses.empty())
                throw std::invalid_argument("local DNF has no clause");
            std::vector<seal::Ciphertext> clauses;
            clauses.reserve(node.dnf_clauses.size());
            for (const auto &clause : node.dnf_clauses)
            {
                if (clause.empty()) throw std::invalid_argument("local DNF clause is empty");
                std::vector<seal::Ciphertext> literals;
                literals.reserve(clause.size());
                for (const auto &literal : clause)
                    literals.push_back(literal_value(literal));
                clauses.push_back(reduce_balanced(
                    std::move(literals), PlanKind::logical_and));
            }
            return reduce_balanced(std::move(clauses), PlanKind::logical_or);
        }

        [[nodiscard]] seal::Ciphertext evaluate_gate(const PlanNode &node)
        {
            if (node.children.size() != 2)
                throw std::invalid_argument("fallback Boolean gate must have two children");
            return combine(
                evaluate(node.children[0]), evaluate(node.children[1]), node.kind);
        }

        const pir::common::BfvParameters &parameters_;
        const InterleavedLayout &layout_;
        const std::vector<std::vector<seal::Ciphertext>> &scan_results_;
        std::size_t fragment_begin_;
        std::size_t fragment_end_;
        std::size_t packed_keyword_count_;
        seal::BatchEncoder &encoder_;
        seal::Evaluator &evaluator_;
        const seal::RelinKeys &relinearization_keys_;
        const seal::GaloisKeys &galois_keys_;
        pir::common::HomomorphicCounters &counters_;
        std::map<std::size_t, seal::Plaintext> block_masks_;
        std::map<std::size_t, seal::Plaintext> transpose_masks_;
        std::map<std::size_t, seal::Ciphertext> packed_leaf_cache_;
        std::map<std::size_t, std::vector<seal::Ciphertext>>
            transposed_container_cache_;
        seal::Plaintext active_blocks_mask_;
        bool active_blocks_mask_ready_{false};
    };

    class Server::Impl
    {
    public:
        Impl(
            pir::common::BfvParameters parameters,
            std::shared_ptr<seal::SEALContext> context,
            seal::RelinKeys relinearization_keys,
            seal::GaloisKeys galois_keys)
            : parameters_(std::move(parameters)),
              layout_(parameters_.polynomial_modulus_degree, parameters_.block_count),
              context_(std::move(context)),
              relinearization_keys_(std::move(relinearization_keys)),
              galois_keys_(std::move(galois_keys)),
              parameter_fingerprint_(
                  "pmkpir-v1:" + pir::common::bfv_parameter_fingerprint(parameters_))
        {
            if (!context_ || !context_->parameters_set())
                throw std::invalid_argument("PMKPIR server requires a valid BFV context");
            evaluator_ = std::make_unique<seal::Evaluator>(*context_);
            encoder_ = std::make_unique<seal::BatchEncoder>(*context_);
        }

        [[nodiscard]] PreprocessedDatabase preprocess(
            const pir::common::Dataset &dataset) const
        {
            const auto bitmap_begin = std::chrono::steady_clock::now();
            const auto bitmap_database = pir::common::build_keyword_database(
                dataset, layout_.region_width());
            PreprocessedDatabase result;
            result.setup_metrics_.bitmap_build_ms +=
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - bitmap_begin).count();
            result.keyword_count_ = bitmap_database.keyword_count();
            result.document_count_ = bitmap_database.document_count();
            result.fragment_count_ = bitmap_database.fragment_count();
            result.keyword_codes_.reserve(result.keyword_count_);
            result.normalized_bitmap_fragments_.reserve(
                result.keyword_count_ * result.fragment_count_);
            const auto gamma = inverse_mod(
                factorial_mod(parameters_.constant_weight, parameters_.plain_modulus),
                parameters_.plain_modulus);
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            std::vector<std::uint64_t> fragment(layout_.region_width(), 0);
            for (std::size_t keyword = 0; keyword < result.keyword_count_; ++keyword)
            {
                const auto keyword_begin = std::chrono::steady_clock::now();
                std::fill(slots.begin(), slots.end(), 0);
                const auto positions = pir::common::unrank_constant_weight_u64(
                    layout_.region_width(), parameters_.constant_weight, keyword);
                for (std::size_t block = 0; block < parameters_.block_count; ++block)
                    for (const auto position : positions)
                        slots[layout_.slot_index(block, position)] = 1;
                seal::Plaintext code;
                encoder_->encode(slots, code);
                result.keyword_codes_.push_back(std::move(code));
                result.setup_metrics_.keyword_encode_ms +=
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - keyword_begin).count();
                for (std::size_t bitmap_fragment = 0;
                     bitmap_fragment < result.fragment_count_;
                     ++bitmap_fragment)
                {
                    const auto fragment_begin = std::chrono::steady_clock::now();
                    bitmap_database.copy_fragment(keyword, bitmap_fragment, fragment);
                    std::fill(slots.begin(), slots.end(), 0);
                    for (std::size_t block = 0; block < parameters_.block_count; ++block)
                        for (std::size_t offset = 0; offset < fragment.size(); ++offset)
                            slots[layout_.slot_index(block, offset)] =
                                multiply_mod(fragment[offset], gamma, parameters_.plain_modulus);
                    seal::Plaintext bitmap;
                    encoder_->encode(slots, bitmap);
                    result.normalized_bitmap_fragments_.push_back(std::move(bitmap));
                    result.setup_metrics_.bitmap_build_ms +=
                        std::chrono::duration<double, std::milli>(
                            std::chrono::steady_clock::now() - fragment_begin).count();
                }
            }
            return result;
        }

        [[nodiscard]] PreprocessedDatabase preprocess(
            const pir::common::Dataset &dataset,
            const WideKeywordCodebook &codebook) const
        {
            // The experiment supplies sparse positions directly, preserving O(Kk) code storage.
            if (codebook.size() != dataset.parameters.keyword_count)
                throw std::invalid_argument("wide codebook row count differs from the dataset");
            if (codebook.code_width() != layout_.region_width())
                throw std::invalid_argument("wide codebook width differs from the PMKPIR layout");
            if (codebook.weight() != parameters_.constant_weight)
                throw std::invalid_argument("wide codebook weight differs from the PMKPIR parameters");

            const auto bitmap_begin = std::chrono::steady_clock::now();
            const auto bitmap_database = pir::common::build_keyword_database(
                dataset, layout_.region_width());
            PreprocessedDatabase result;
            result.setup_metrics_.bitmap_build_ms +=
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - bitmap_begin).count();
            result.keyword_count_ = bitmap_database.keyword_count();
            result.document_count_ = bitmap_database.document_count();
            result.fragment_count_ = bitmap_database.fragment_count();
            result.keyword_codes_.reserve(result.keyword_count_);
            result.normalized_bitmap_fragments_.reserve(
                result.keyword_count_ * result.fragment_count_);
            const auto gamma = inverse_mod(
                factorial_mod(parameters_.constant_weight, parameters_.plain_modulus),
                parameters_.plain_modulus);
            std::vector<std::uint64_t> slots(parameters_.polynomial_modulus_degree, 0);
            std::vector<std::uint64_t> fragment(layout_.region_width(), 0);
            for (std::size_t keyword = 0; keyword < result.keyword_count_; ++keyword)
            {
                const auto keyword_begin = std::chrono::steady_clock::now();
                std::fill(slots.begin(), slots.end(), 0);
                for (std::size_t block = 0; block < parameters_.block_count; ++block)
                    for (const auto position : codebook.positions(keyword))
                        slots[layout_.slot_index(block, position)] = 1;
                seal::Plaintext code;
                encoder_->encode(slots, code);
                result.keyword_codes_.push_back(std::move(code));
                result.setup_metrics_.keyword_encode_ms +=
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - keyword_begin).count();
                for (std::size_t bitmap_fragment = 0;
                     bitmap_fragment < result.fragment_count_;
                     ++bitmap_fragment)
                {
                    const auto fragment_begin = std::chrono::steady_clock::now();
                    bitmap_database.copy_fragment(keyword, bitmap_fragment, fragment);
                    std::fill(slots.begin(), slots.end(), 0);
                    for (std::size_t block = 0; block < parameters_.block_count; ++block)
                        for (std::size_t offset = 0; offset < fragment.size(); ++offset)
                            slots[layout_.slot_index(block, offset)] =
                                multiply_mod(fragment[offset], gamma, parameters_.plain_modulus);
                    seal::Plaintext bitmap;
                    encoder_->encode(slots, bitmap);
                    result.normalized_bitmap_fragments_.push_back(std::move(bitmap));
                    result.setup_metrics_.bitmap_build_ms +=
                        std::chrono::duration<double, std::milli>(
                            std::chrono::steady_clock::now() - fragment_begin).count();
                }
            }
            return result;
        }

        void save_preprocessed(
            const PreprocessedDatabase &database,
            const std::filesystem::path &path,
            const std::string &dataset_sha256) const
        {
            if (database.keyword_codes_.size() != database.keyword_count_ ||
                database.normalized_bitmap_fragments_.size() !=
                    database.keyword_count_ * database.fragment_count_)
            {
                throw std::invalid_argument("PMKPIR preprocessed database shape is invalid");
            }
            std::vector<seal::Plaintext> plaintexts;
            plaintexts.reserve(
                database.keyword_codes_.size() +
                database.normalized_bitmap_fragments_.size());
            plaintexts.insert(
                plaintexts.end(),
                database.keyword_codes_.begin(),
                database.keyword_codes_.end());
            plaintexts.insert(
                plaintexts.end(),
                database.normalized_bitmap_fragments_.begin(),
                database.normalized_bitmap_fragments_.end());
            pir::common::save_plaintexts_atomic(
                path, plaintexts, dataset_sha256, parameter_fingerprint_);
        }

        [[nodiscard]] PreprocessedDatabase load_preprocessed(
            const std::filesystem::path &path,
            const std::string &dataset_sha256,
            const std::size_t keyword_count,
            const std::size_t document_count) const
        {
            if (keyword_count == 0 || document_count == 0)
                throw std::invalid_argument("PMKPIR cache dimensions must be positive");
            const std::size_t fragment_count = ceil_divide(
                document_count, layout_.region_width());
            auto plaintexts = pir::common::load_plaintexts(
                path, *context_, dataset_sha256, parameter_fingerprint_);
            if (plaintexts.size() != keyword_count * (fragment_count + 1))
                throw std::runtime_error("PMKPIR plaintext cache count mismatch");
            PreprocessedDatabase result;
            result.keyword_count_ = keyword_count;
            result.document_count_ = document_count;
            result.fragment_count_ = fragment_count;
            result.keyword_codes_.assign(
                std::make_move_iterator(plaintexts.begin()),
                std::make_move_iterator(plaintexts.begin() +
                    static_cast<std::ptrdiff_t>(keyword_count)));
            result.normalized_bitmap_fragments_.assign(
                std::make_move_iterator(plaintexts.begin() +
                    static_cast<std::ptrdiff_t>(keyword_count)),
                std::make_move_iterator(plaintexts.end()));
            return result;
        }

        [[nodiscard]] seal::Ciphertext equality_root(
            const seal::Ciphertext &query,
            const seal::Plaintext &code,
            pir::common::HomomorphicCounters &counters) const
        {
            seal::Ciphertext inner_product;
            evaluator_->multiply_plain(query, code, inner_product);
            ++counters.plaintext_multiplications;
            for (const int step : layout_.reduction_rotation_steps())
            {
                seal::Ciphertext rotated;
                evaluator_->rotate_rows(inner_product, step, galois_keys_, rotated);
                evaluator_->add_inplace(inner_product, rotated);
                ++counters.row_rotations;
                ++counters.additions;
            }
            std::vector<seal::Ciphertext> factors;
            factors.reserve(parameters_.constant_weight);
            for (std::size_t root = 0; root < parameters_.constant_weight; ++root)
            {
                auto factor = inner_product;
                if (root != 0)
                {
                    std::vector<std::uint64_t> scalar(
                        parameters_.polynomial_modulus_degree,
                        (parameters_.plain_modulus - root) % parameters_.plain_modulus);
                    seal::Plaintext negative_root;
                    encoder_->encode(scalar, negative_root);
                    evaluator_->add_plain_inplace(factor, negative_root);
                }
                factors.push_back(std::move(factor));
            }
            while (factors.size() > 1)
            {
                std::vector<seal::Ciphertext> next;
                next.reserve((factors.size() + 1) / 2);
                for (std::size_t index = 0; index < factors.size(); index += 2)
                {
                    if (index + 1 == factors.size())
                    {
                        next.push_back(std::move(factors[index]));
                        continue;
                    }
                    const bool is_final_root = factors.size() == 2;
                    evaluator_->multiply_inplace(factors[index], factors[index + 1]);
                    ++counters.ciphertext_multiplications;
                    if (!is_final_root)
                    {
                        evaluator_->relinearize_inplace(
                            factors[index], relinearization_keys_);
                        ++counters.relinearizations;
                    }
                    next.push_back(std::move(factors[index]));
                }
                factors = std::move(next);
            }
            return std::move(factors.front());
        }

        [[nodiscard]] EncryptedSelection evaluate(
            const EncryptedQuery &query,
            const PreprocessedDatabase &database) const
        {
            if (!query.compiled.root || query.compiled.block_count != parameters_.block_count)
                throw std::invalid_argument("PMKPIR compiled query is invalid");
            const std::size_t container_count = ceil_divide(
                query.compiled.packed_keywords.size(), parameters_.block_count);
            if (query.ciphertexts.size() != container_count)
                throw std::invalid_argument("PMKPIR encrypted query container count mismatch");
            if (database.keyword_codes_.size() != database.keyword_count_ ||
                database.normalized_bitmap_fragments_.size() !=
                    database.keyword_count_ * database.fragment_count_)
            {
                throw std::invalid_argument("PMKPIR preprocessed database shape is invalid");
            }
            EncryptedSelection result;
            std::vector<std::vector<seal::Ciphertext>> scan_results(
                container_count,
                std::vector<seal::Ciphertext>(database.fragment_count_));
            std::vector<std::vector<bool>> initialized(
                container_count,
                std::vector<bool>(database.fragment_count_, false));
            const auto keyword_match_begin = std::chrono::steady_clock::now();

            // Loop order keeps one accumulator per (container,fragment), O(alpha*f),
            // and never stores the O(alpha*K*f) row products. The final size-3 roots
            // are relinearized only after all K rows have been aggregated.
            for (std::size_t container = 0; container < container_count; ++container)
            {
                for (std::size_t row = 0; row < database.keyword_count_; ++row)
                {
                    const auto root = equality_root(
                        query.ciphertexts[container],
                        database.keyword_codes_[row],
                        result.metrics.scan_operations);
                    for (std::size_t fragment = 0; fragment < database.fragment_count_; ++fragment)
                    {
                        const auto &bitmap = database.normalized_bitmap_fragments_[
                            row * database.fragment_count_ + fragment];
                        // A zero bitmap contributes nothing to the scan sum. Skipping it avoids
                        // constructing a transparent ciphertext without changing the result.
                        if (bitmap.is_zero()) continue;
                        seal::Ciphertext product;
                        evaluator_->multiply_plain(root, bitmap, product);
                        ++result.metrics.scan_operations.plaintext_multiplications;
                        if (!initialized[container][fragment])
                        {
                            scan_results[container][fragment] = std::move(product);
                            initialized[container][fragment] = true;
                        }
                        else
                        {
                            evaluator_->add_inplace(scan_results[container][fragment], product);
                            ++result.metrics.scan_operations.additions;
                        }
                    }
                }
                if (parameters_.constant_weight >= 2)
                {
                    for (auto &ciphertext : scan_results[container])
                    {
                        evaluator_->relinearize_inplace(ciphertext, relinearization_keys_);
                        ++result.metrics.scan_operations.relinearizations;
                    }
                }
            }
            result.metrics.keyword_match_ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - keyword_match_begin).count();

            if (database.fragment_count_ == 1)
            {
                BooleanEvaluator boolean_evaluator(
                    parameters_, layout_, scan_results, 0,
                    *encoder_, *evaluator_, relinearization_keys_, galois_keys_,
                    result.metrics.boolean_operations);
                const auto boolean_begin = std::chrono::steady_clock::now();
                auto value = boolean_evaluator.evaluate(query.compiled.root);
                result.metrics.boolean_evaluation_ms +=
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - boolean_begin).count();
                const auto serialization_begin = std::chrono::steady_clock::now();
                result.serialized_size_bytes = checked_add(
                    result.serialized_size_bytes, serialized_size(value));
                result.serialization_ms += std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - serialization_begin).count();
                result.fragments.push_back(std::move(value));
                return result;
            }

            const std::size_t response_count = ceil_divide(
                database.fragment_count_, parameters_.block_count);
            result.fragments.reserve(response_count);
            // Each response uses its B logical blocks for B adjacent document fragments.
            // This leaves the preprocessed plaintext layout unchanged while reducing the
            // response count from ceil(M/w) to ceil(M/N).
            for (std::size_t fragment_begin = 0;
                 fragment_begin < database.fragment_count_;
                 fragment_begin += parameters_.block_count)
            {
                const std::size_t fragment_end = std::min(
                    database.fragment_count_, fragment_begin + parameters_.block_count);
                PackedFragmentBooleanEvaluator boolean_evaluator(
                    parameters_, layout_, scan_results, fragment_begin, fragment_end,
                    query.compiled.packed_keywords.size(),
                    *encoder_, *evaluator_, relinearization_keys_, galois_keys_,
                    result.metrics.boolean_operations);
                const auto boolean_begin = std::chrono::steady_clock::now();
                auto value = boolean_evaluator.evaluate(query.compiled.root);
                result.metrics.boolean_evaluation_ms +=
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - boolean_begin).count();
                const auto serialization_begin = std::chrono::steady_clock::now();
                result.serialized_size_bytes = checked_add(
                    result.serialized_size_bytes, serialized_size(value));
                result.serialization_ms += std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - serialization_begin).count();
                result.fragments.push_back(std::move(value));
            }
            return result;
        }

        pir::common::BfvParameters parameters_;
        InterleavedLayout layout_;
        std::shared_ptr<seal::SEALContext> context_;
        seal::RelinKeys relinearization_keys_;
        seal::GaloisKeys galois_keys_;
        std::unique_ptr<seal::Evaluator> evaluator_;
        std::unique_ptr<seal::BatchEncoder> encoder_;
        std::string parameter_fingerprint_;
    };

    Server::Server(
        pir::common::BfvParameters parameters,
        std::shared_ptr<seal::SEALContext> context,
        seal::RelinKeys relinearization_keys,
        seal::GaloisKeys galois_keys)
        : impl_(std::make_unique<Impl>(
              std::move(parameters), std::move(context),
              std::move(relinearization_keys), std::move(galois_keys))) {}
    Server::~Server() = default;
    Server::Server(Server &&) noexcept = default;
    Server &Server::operator=(Server &&) noexcept = default;
    PreprocessedDatabase Server::preprocess(const pir::common::Dataset &dataset) const
    {
        return impl_->preprocess(dataset);
    }
    PreprocessedDatabase Server::preprocess(
        const pir::common::Dataset &dataset,
        const WideKeywordCodebook &codebook) const
    {
        return impl_->preprocess(dataset, codebook);
    }
    void Server::save_preprocessed(
        const PreprocessedDatabase &database,
        const std::filesystem::path &path,
        const std::string &dataset_sha256) const
    {
        impl_->save_preprocessed(database, path, dataset_sha256);
    }
    PreprocessedDatabase Server::load_preprocessed(
        const std::filesystem::path &path,
        const std::string &dataset_sha256,
        const std::size_t keyword_count,
        const std::size_t document_count) const
    {
        return impl_->load_preprocessed(
            path, dataset_sha256, keyword_count, document_count);
    }
    EncryptedSelection Server::evaluate(
        const EncryptedQuery &query,
        const PreprocessedDatabase &database) const
    {
        return impl_->evaluate(query, database);
    }
}
