#include "pir/common/persistence.hpp"

#include "pir/common/hash.hpp"

#include <seal/version.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace pir::common
{
    namespace
    {
        constexpr std::array<char, 8> dataset_magic{'P', 'I', 'R', 'D', 'A', 'T', 'A', '1'};
        constexpr std::array<char, 8> plaintext_magic{'P', 'I', 'R', 'P', 'L', 'N', '0', '1'};
        constexpr std::uint64_t format_version = 1;
        std::atomic<std::uint64_t> temporary_counter{0};

        class TemporaryFile
        {
        public:
            explicit TemporaryFile(std::filesystem::path path) : path_(std::move(path)) {}
            ~TemporaryFile()
            {
                if (!released_)
                {
                    std::error_code ignored;
                    std::filesystem::remove(path_, ignored);
                }
            }
            TemporaryFile(const TemporaryFile &) = delete;
            TemporaryFile &operator=(const TemporaryFile &) = delete;
            [[nodiscard]] const std::filesystem::path &path() const noexcept { return path_; }
            void release() noexcept { released_ = true; }

        private:
            std::filesystem::path path_;
            bool released_ = false;
        };

        [[nodiscard]] std::filesystem::path make_temporary_path(
            const std::filesystem::path &target)
        {
            const auto nonce = static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            return target.string() + "." + std::to_string(nonce) + "." +
                   std::to_string(temporary_counter.fetch_add(1)) + ".tmp";
        }

        void prepare_parent(const std::filesystem::path &path)
        {
            if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
        }

        void replace_atomically(
            const std::filesystem::path &temporary,
            const std::filesystem::path &target)
        {
            std::error_code error;
            std::filesystem::rename(temporary, target, error);
            if (error)
                throw std::runtime_error(
                    "atomic rename failed for " + target.string() + ": " + error.message());
        }

        void write_u64(std::ostream &stream, const std::uint64_t value)
        {
            std::array<char, 8> bytes{};
            for (std::size_t index = 0; index < bytes.size(); ++index)
                bytes[index] = static_cast<char>((value >> (index * 8U)) & 0xffU);
            stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            if (!stream) throw std::runtime_error("binary cache write failed");
        }

        [[nodiscard]] std::uint64_t read_u64(std::istream &stream)
        {
            std::array<unsigned char, 8> bytes{};
            stream.read(reinterpret_cast<char *>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
            if (!stream) throw std::runtime_error("truncated binary cache");
            std::uint64_t value = 0;
            for (std::size_t index = 0; index < bytes.size(); ++index)
                value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
            return value;
        }

        void write_string(std::ostream &stream, const std::string &value)
        {
            write_u64(stream, value.size());
            stream.write(value.data(), static_cast<std::streamsize>(value.size()));
            if (!stream) throw std::runtime_error("string cache write failed");
        }

        [[nodiscard]] std::string read_string(std::istream &stream)
        {
            const auto size = read_u64(stream);
            if (size > 1024 * 1024)
                throw std::runtime_error("cache string exceeds one MiB safety limit");
            std::string value(static_cast<std::size_t>(size), '\0');
            stream.read(value.data(), static_cast<std::streamsize>(value.size()));
            if (!stream) throw std::runtime_error("truncated cache string");
            return value;
        }

        [[nodiscard]] std::string seal_version()
        {
            return std::to_string(SEAL_VERSION_MAJOR) + "." +
                   std::to_string(SEAL_VERSION_MINOR) + "." +
                   std::to_string(SEAL_VERSION_PATCH);
        }

        [[nodiscard]] std::filesystem::path sidecar_path(
            const std::filesystem::path &path)
        {
            return path.string() + ".json";
        }

        [[nodiscard]] std::string json_string(
            const std::string &json,
            const std::string_view key)
        {
            const std::string marker = "\"" + std::string(key) + "\":\"";
            const auto begin = json.find(marker);
            if (begin == std::string::npos)
                throw std::runtime_error("manifest is missing " + std::string(key));
            const auto value_begin = begin + marker.size();
            const auto end = json.find('"', value_begin);
            if (end == std::string::npos)
                throw std::runtime_error("manifest has an unterminated " + std::string(key));
            return json.substr(value_begin, end - value_begin);
        }

        [[nodiscard]] CacheManifest read_manifest(const std::filesystem::path &path)
        {
            std::ifstream stream(path, std::ios::binary);
            if (!stream) throw std::runtime_error("cannot open manifest: " + path.string());
            const std::string json(
                (std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
            if (json.find("\"format_version\":1") == std::string::npos)
                throw std::runtime_error("manifest format_version is unsupported");
            return {
                1,
                json_string(json, "kind"),
                json_string(json, "parameter_fingerprint"),
                json_string(json, "data_sha256"),
                json_string(json, "seal_version")};
        }

        void write_manifest_atomic(
            const std::filesystem::path &path,
            const CacheManifest &manifest,
            const Dataset *dataset = nullptr)
        {
            prepare_parent(path);
            TemporaryFile temporary(make_temporary_path(path));
            std::ofstream stream(temporary.path(), std::ios::binary | std::ios::trunc);
            if (!stream) throw std::runtime_error("cannot create manifest: " + path.string());
            stream << "{\n"
                   << "  \"format_version\":1,\n"
                   << "  \"kind\":\"" << manifest.kind << "\",\n"
                   << "  \"parameter_fingerprint\":\""
                   << manifest.parameter_fingerprint << "\",\n"
                   << "  \"data_sha256\":\"" << manifest.data_sha256 << "\",\n"
                   << "  \"seal_version\":\"" << manifest.seal_version << "\"";
            if (dataset != nullptr)
            {
                const auto frequencies = keyword_frequencies(*dataset);
                const auto [minimum, maximum] = std::minmax_element(
                    frequencies.begin(), frequencies.end());
                const double mean = static_cast<double>(std::accumulate(
                    frequencies.begin(), frequencies.end(), std::size_t{0})) /
                    static_cast<double>(frequencies.size());
                double squared_deviation = 0.0;
                for (const auto frequency : frequencies)
                {
                    const double difference = static_cast<double>(frequency) - mean;
                    squared_deviation += difference * difference;
                }
                const double standard_deviation = std::sqrt(
                    squared_deviation / static_cast<double>(frequencies.size()));
                stream << ",\n  \"document_count\":" << dataset->documents.size()
                       << ",\n  \"keyword_count\":" << frequencies.size()
                       << ",\n  \"frequency_min\":" << *minimum
                       << ",\n  \"frequency_max\":" << *maximum
                       << ",\n  \"frequency_mean\":" << mean
                       << ",\n  \"frequency_stddev\":" << standard_deviation
                       << ",\n  \"keyword_frequencies\":[";
                for (std::size_t index = 0; index < frequencies.size(); ++index)
                {
                    if (index != 0) stream << ',';
                    stream << frequencies[index];
                }
                stream << "],\n  \"document_keyword_counts\":[";
                for (std::size_t index = 0; index < dataset->documents.size(); ++index)
                {
                    if (index != 0) stream << ',';
                    stream << dataset->documents[index].keyword_ids.size();
                }
                stream << ']';
            }
            stream << "\n}\n";
            stream.close();
            if (!stream) throw std::runtime_error("manifest flush failed: " + path.string());
            replace_atomically(temporary.path(), path);
            temporary.release();
        }

        void validate_manifest(
            const CacheManifest &manifest,
            const std::string_view kind,
            const std::string &parameter_fingerprint,
            const std::string &dataset_sha256 = {})
        {
            if (manifest.kind != kind)
                throw std::runtime_error("cache manifest kind mismatch");
            if (manifest.parameter_fingerprint != parameter_fingerprint)
                throw std::runtime_error("cache parameter fingerprint mismatch");
            if (!dataset_sha256.empty() && manifest.data_sha256 != dataset_sha256)
                throw std::runtime_error("cache dataset SHA-256 mismatch");
            if (manifest.seal_version != seal_version())
                throw std::runtime_error("cache SEAL version mismatch");
        }

        void verify_file_hash(
            const std::filesystem::path &path,
            const std::string &expected)
        {
            if (sha256_file_hex(path) != expected)
                throw std::runtime_error("cache SHA-256 mismatch: " + path.string());
        }
    }

    std::string bfv_parameter_fingerprint(const BfvParameters &parameters)
    {
        std::ostringstream canonical;
        canonical << parameters.polynomial_modulus_degree << '|'
                  << parameters.plain_modulus << '|'
                  << parameters.block_count << '|'
                  << parameters.constant_weight << '|'
                  << parameters.minimum_noise_budget_bits;
        for (const auto bits : parameters.coefficient_modulus_bits)
            canonical << '|' << bits;
        const auto text = canonical.str();
        return sha256_hex(
            "pir-bfv-parameters-v1",
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(text.data()), text.size()));
    }

    CacheManifest save_dataset_atomic(
        const std::filesystem::path &data_path,
        const std::filesystem::path &manifest_path,
        const Dataset &dataset,
        const std::string &parameter_fingerprint)
    {
        prepare_parent(data_path);
        TemporaryFile temporary(make_temporary_path(data_path));
        std::ofstream stream(temporary.path(), std::ios::binary | std::ios::trunc);
        if (!stream) throw std::runtime_error("cannot create dataset: " + data_path.string());
        stream.write(dataset_magic.data(), dataset_magic.size());
        write_u64(stream, format_version);
        write_u64(stream, dataset.parameters.document_count);
        write_u64(stream, dataset.parameters.keyword_count);
        write_u64(stream, dataset.parameters.keywords_per_document);
        write_u64(stream, dataset.parameters.payload_bytes);
        write_u64(stream, dataset.parameters.seed);
        write_u64(stream, dataset.documents.size());
        for (const auto &document : dataset.documents)
        {
            write_u64(stream, document.id);
            write_u64(stream, document.keyword_ids.size());
            for (const auto keyword : document.keyword_ids) write_u64(stream, keyword);
            write_u64(stream, document.payload.size());
            stream.write(
                reinterpret_cast<const char *>(document.payload.data()),
                static_cast<std::streamsize>(document.payload.size()));
            if (!stream) throw std::runtime_error("dataset payload write failed");
        }
        stream.close();
        if (!stream) throw std::runtime_error("dataset flush failed: " + data_path.string());
        const CacheManifest manifest{
            1, "dataset", parameter_fingerprint,
            sha256_file_hex(temporary.path()), seal_version()};
        replace_atomically(temporary.path(), data_path);
        temporary.release();
        // Persist O(K+M) summary vectors once so audit tooling never rescans the
        // O(Md) dataset. The modest manifest space cost removes repeated I/O.
        write_manifest_atomic(manifest_path, manifest, &dataset);
        return manifest;
    }

    LoadedDataset load_dataset(
        const std::filesystem::path &data_path,
        const std::filesystem::path &manifest_path,
        const std::string &expected_parameter_fingerprint)
    {
        const auto manifest = read_manifest(manifest_path);
        validate_manifest(manifest, "dataset", expected_parameter_fingerprint);
        verify_file_hash(data_path, manifest.data_sha256);

        std::ifstream stream(data_path, std::ios::binary);
        if (!stream) throw std::runtime_error("cannot open dataset: " + data_path.string());
        std::array<char, 8> magic{};
        stream.read(magic.data(), magic.size());
        if (magic != dataset_magic || read_u64(stream) != format_version)
            throw std::runtime_error("dataset header is invalid");
        Dataset dataset;
        const auto read_size = [&stream](const char *name) {
            const auto value = read_u64(stream);
            if (value > std::numeric_limits<std::size_t>::max())
                throw std::runtime_error(std::string(name) + " exceeds size_t");
            return static_cast<std::size_t>(value);
        };
        dataset.parameters.document_count = read_size("document_count");
        dataset.parameters.keyword_count = read_size("keyword_count");
        dataset.parameters.keywords_per_document = read_size("keywords_per_document");
        dataset.parameters.payload_bytes = read_size("payload_bytes");
        dataset.parameters.seed = read_u64(stream);
        const auto count = read_size("stored document count");
        if (count != dataset.parameters.document_count)
            throw std::runtime_error("stored document count differs from parameters");
        dataset.documents.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
        {
            Document document;
            document.id = read_size("document id");
            const auto keyword_count = read_size("document keyword count");
            if (keyword_count > dataset.parameters.keyword_count)
                throw std::runtime_error("stored document keyword count is invalid");
            document.keyword_ids.reserve(keyword_count);
            for (std::size_t keyword = 0; keyword < keyword_count; ++keyword)
            {
                const auto value = read_u64(stream);
                if (value >= dataset.parameters.keyword_count ||
                    value > std::numeric_limits<std::uint32_t>::max())
                    throw std::runtime_error("stored keyword id is invalid");
                document.keyword_ids.push_back(static_cast<std::uint32_t>(value));
            }
            const auto payload_size = read_size("document payload size");
            if (payload_size != dataset.parameters.payload_bytes)
                throw std::runtime_error("stored payload size differs from parameters");
            document.payload.resize(payload_size);
            stream.read(
                reinterpret_cast<char *>(document.payload.data()),
                static_cast<std::streamsize>(payload_size));
            if (!stream) throw std::runtime_error("truncated dataset payload");
            dataset.documents.push_back(std::move(document));
        }
        if (stream.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("dataset contains trailing bytes");
        return {std::move(dataset), manifest};
    }

    void save_plaintexts_atomic(
        const std::filesystem::path &path,
        const std::vector<seal::Plaintext> &plaintexts,
        const std::string &dataset_sha256,
        const std::string &parameter_fingerprint)
    {
        prepare_parent(path);
        TemporaryFile temporary(make_temporary_path(path));
        std::ofstream stream(temporary.path(), std::ios::binary | std::ios::trunc);
        if (!stream) throw std::runtime_error("cannot create plaintext cache: " + path.string());
        stream.write(plaintext_magic.data(), plaintext_magic.size());
        write_u64(stream, format_version);
        write_string(stream, dataset_sha256);
        write_string(stream, parameter_fingerprint);
        write_u64(stream, plaintexts.size());
        for (const auto &plaintext : plaintexts)
        {
            if (plaintext.save(stream, seal::compr_mode_type::none) < 0)
                throw std::runtime_error("SEAL plaintext save failed");
        }
        stream.close();
        if (!stream) throw std::runtime_error("plaintext cache flush failed");
        const CacheManifest manifest{
            1, "plaintexts", parameter_fingerprint,
            sha256_file_hex(temporary.path()), seal_version()};
        replace_atomically(temporary.path(), path);
        temporary.release();
        write_manifest_atomic(sidecar_path(path), manifest);
    }

    std::vector<seal::Plaintext> load_plaintexts(
        const std::filesystem::path &path,
        const seal::SEALContext &context,
        const std::string &expected_dataset_sha256,
        const std::string &expected_parameter_fingerprint)
    {
        const auto manifest = read_manifest(sidecar_path(path));
        validate_manifest(manifest, "plaintexts", expected_parameter_fingerprint);
        verify_file_hash(path, manifest.data_sha256);
        std::ifstream stream(path, std::ios::binary);
        if (!stream) throw std::runtime_error("cannot open plaintext cache: " + path.string());
        std::array<char, 8> magic{};
        stream.read(magic.data(), magic.size());
        if (magic != plaintext_magic || read_u64(stream) != format_version)
            throw std::runtime_error("plaintext cache header is invalid");
        if (read_string(stream) != expected_dataset_sha256)
            throw std::runtime_error("plaintext cache dataset SHA-256 mismatch");
        if (read_string(stream) != expected_parameter_fingerprint)
            throw std::runtime_error("plaintext cache parameter fingerprint mismatch");
        const auto count = read_u64(stream);
        if (count > std::numeric_limits<std::size_t>::max())
            throw std::runtime_error("plaintext cache count exceeds size_t");
        std::vector<seal::Plaintext> plaintexts;
        plaintexts.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index = 0; index < count; ++index)
        {
            seal::Plaintext plaintext;
            plaintext.load(context, stream);
            plaintexts.push_back(std::move(plaintext));
        }
        if (stream.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("plaintext cache contains trailing bytes");
        return plaintexts;
    }
}
