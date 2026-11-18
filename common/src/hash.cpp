#include "pir/common/hash.hpp"

#include <openssl/evp.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace pir::common
{
    namespace
    {
        using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

        [[nodiscard]] DigestContext make_digest_context()
        {
            DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
                throw std::runtime_error("SHA-256 initialization failed");
            return context;
        }

        void update(EVP_MD_CTX *context, const void *data, const std::size_t size)
        {
            if (size != 0 && EVP_DigestUpdate(context, data, size) != 1)
                throw std::runtime_error("SHA-256 update failed");
        }

        [[nodiscard]] std::vector<std::uint8_t> finish(EVP_MD_CTX *context)
        {
            std::vector<std::uint8_t> digest(32);
            unsigned int length = 0;
            if (EVP_DigestFinal_ex(context, digest.data(), &length) != 1 ||
                length != digest.size())
            {
                throw std::runtime_error("SHA-256 finalization failed");
            }
            return digest;
        }

        [[nodiscard]] std::string hex(const std::vector<std::uint8_t> &bytes)
        {
            std::ostringstream stream;
            stream << std::hex << std::setfill('0');
            for (const auto byte : bytes) stream << std::setw(2) << static_cast<unsigned>(byte);
            return stream.str();
        }
    }

    std::vector<std::uint8_t> sha256(
        const std::string_view domain,
        const std::span<const std::uint8_t> bytes)
    {
        auto context = make_digest_context();
        update(context.get(), domain.data(), domain.size());
        const std::uint8_t separator = 0;
        update(context.get(), &separator, sizeof(separator));
        update(context.get(), bytes.data(), bytes.size());
        return finish(context.get());
    }

    std::string sha256_hex(
        const std::string_view domain,
        const std::span<const std::uint8_t> bytes)
    {
        return hex(sha256(domain, bytes));
    }

    std::string sha256_file_hex(const std::filesystem::path &path)
    {
        std::ifstream stream(path, std::ios::binary);
        if (!stream) throw std::runtime_error("cannot open file for SHA-256: " + path.string());
        auto context = make_digest_context();
        std::array<char, 64 * 1024> buffer{};
        while (stream)
        {
            stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            update(context.get(), buffer.data(), static_cast<std::size_t>(stream.gcount()));
        }
        if (!stream.eof()) throw std::runtime_error("failed while hashing file: " + path.string());
        return hex(finish(context.get()));
    }
}
