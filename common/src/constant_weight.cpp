#include "pir/common/constant_weight.hpp"

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace pir::common
{
    namespace
    {
        using BigNumber = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

        [[nodiscard]] BigNumber make_number()
        {
            BigNumber value(BN_new(), BN_free);
            if (!value) throw std::bad_alloc();
            return value;
        }

        [[nodiscard]] BigNumber binomial(
            const std::size_t width,
            std::size_t weight)
        {
            auto result = make_number();
            if (weight > width)
            {
                BN_zero(result.get());
                return result;
            }
            weight = std::min(weight, width - weight);
            if (BN_one(result.get()) != 1)
                throw std::runtime_error("BIGNUM initialization failed");
            for (std::size_t index = 1; index <= weight; ++index)
            {
                if (BN_mul_word(result.get(), width - weight + index) != 1 ||
                    BN_div_word(result.get(), index) == static_cast<BN_ULONG>(-1))
                {
                    throw std::runtime_error("BIGNUM binomial calculation failed");
                }
            }
            return result;
        }

        [[nodiscard]] BigNumber power_of_two(const std::size_t bits)
        {
            auto value = make_number();
            if (BN_one(value.get()) != 1 ||
                BN_lshift(value.get(), value.get(), bits) != 1)
            {
                throw std::runtime_error("BIGNUM power-of-two calculation failed");
            }
            return value;
        }

        void validate_shape(const std::size_t width, const std::size_t weight)
        {
            if (width == 0) throw std::invalid_argument("width must be positive");
            if (weight == 0 || weight > width)
                throw std::invalid_argument("weight must be in [1,width]");
        }
    }

    std::string binomial_decimal(const std::size_t width, const std::size_t weight)
    {
        const auto value = binomial(width, weight);
        char *decimal = BN_bn2dec(value.get());
        if (!decimal) throw std::runtime_error("BIGNUM decimal conversion failed");
        const std::string result(decimal);
        OPENSSL_free(decimal);
        return result;
    }

    std::size_t minimum_constant_weight(
        const std::size_t width,
        const std::size_t public_domain_bits)
    {
        if (width == 0 || public_domain_bits == 0)
            throw std::invalid_argument("width and public_domain_bits must be positive");
        const auto required = power_of_two(public_domain_bits);
        for (std::size_t weight = 1; weight <= width / 2; ++weight)
        {
            if (BN_cmp(binomial(width, weight).get(), required.get()) >= 0)
                return weight;
        }
        throw std::invalid_argument("public_domain_bits exceed every constant-weight capacity");
    }

    std::vector<std::size_t> unrank_constant_weight_bytes(
        const std::size_t width,
        const std::size_t weight,
        const std::span<const std::uint8_t> big_endian_rank)
    {
        validate_shape(width, weight);
        if (big_endian_rank.empty())
            throw std::invalid_argument("rank byte string must not be empty");
        BigNumber remaining(
            BN_bin2bn(
                big_endian_rank.data(),
                static_cast<int>(big_endian_rank.size()),
                nullptr),
            BN_free);
        if (!remaining) throw std::runtime_error("BIGNUM rank conversion failed");
        const auto capacity = binomial(width, weight);
        if (BN_cmp(remaining.get(), capacity.get()) >= 0)
            throw std::out_of_range("constant-weight rank is outside C(width,weight)");

        std::vector<std::size_t> positions;
        positions.reserve(weight);
        std::size_t candidate = 0;
        for (std::size_t position = 0; position < weight; ++position)
        {
            const std::size_t remaining_positions = weight - position;
            auto skipped_count = binomial(
                width - candidate - 1,
                remaining_positions - 1);
            while (BN_cmp(remaining.get(), skipped_count.get()) >= 0)
            {
                if (BN_sub(remaining.get(), remaining.get(), skipped_count.get()) != 1)
                    throw std::runtime_error("BIGNUM rank subtraction failed");
                const std::size_t old_n = width - candidate - 1;
                const std::size_t choose = remaining_positions - 1;
                ++candidate;
                if (candidate > width - remaining_positions)
                    throw std::logic_error("constant-weight unranking exhausted candidates");
                if (choose != 0)
                {
                    // C(n-1,r)=C(n,r)*(n-r)/n updates one candidate in O(1)
                    // big-integer word operations, so the full scan is O(width+k^2).
                    if (BN_mul_word(skipped_count.get(), old_n - choose) != 1 ||
                        BN_div_word(skipped_count.get(), old_n) ==
                            static_cast<BN_ULONG>(-1))
                    {
                        throw std::runtime_error("BIGNUM incremental binomial update failed");
                    }
                }
            }
            positions.push_back(candidate);
            ++candidate;
        }
        return positions;
    }

    std::vector<std::size_t> unrank_constant_weight_u64(
        const std::size_t width,
        const std::size_t weight,
        const std::uint64_t rank)
    {
        std::array<std::uint8_t, 8> bytes{};
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[bytes.size() - index - 1] =
                static_cast<std::uint8_t>((rank >> (index * 8U)) & 0xffU);
        return unrank_constant_weight_bytes(width, weight, bytes);
    }
}
