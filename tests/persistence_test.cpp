#include "pir/common/bfv.hpp"
#include "pir/common/dataset.hpp"
#include "pir/common/persistence.hpp"

#include <seal/seal.h>

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    void require(const bool condition, const char *message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    class TemporaryDirectory
    {
    public:
        TemporaryDirectory()
            : path_(std::filesystem::temp_directory_path() /
                    ("pir-persistence-test-" + std::to_string(std::rand())))
        {
            std::filesystem::create_directories(path_);
        }

        ~TemporaryDirectory()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }

        [[nodiscard]] const std::filesystem::path &path() const noexcept { return path_; }

    private:
        std::filesystem::path path_;
    };
}

int main()
{
    try
    {
        TemporaryDirectory temporary;
        const auto dataset = pir::common::generate_balanced_dataset({8, 4, 2, 7, 20261027});
        const auto data_path = temporary.path() / "shared.pirdata";
        const auto manifest_path = temporary.path() / "shared.json";
        const std::string fingerprint = "fixture-parameters-v1";

        const auto saved_manifest = pir::common::save_dataset_atomic(
            data_path, manifest_path, dataset, fingerprint);
        require(std::filesystem::exists(data_path), "dataset file was not created");
        require(std::filesystem::exists(manifest_path), "manifest file was not created");
        require(saved_manifest.format_version == 1, "unexpected format version");
        require(saved_manifest.parameter_fingerprint == fingerprint, "fingerprint changed");
        require(saved_manifest.data_sha256.size() == 64, "SHA-256 must be hexadecimal");
        {
            std::ifstream manifest_stream(manifest_path);
            const std::string manifest_text(
                (std::istreambuf_iterator<char>(manifest_stream)),
                std::istreambuf_iterator<char>());
            require(
                manifest_text.find("\"keyword_frequencies\":[4,4,4,4]") !=
                    std::string::npos,
                "dataset manifest must persist all keyword frequencies");
            require(
                manifest_text.find("\"document_keyword_counts\":[2,2,2,2,2,2,2,2]") !=
                    std::string::npos,
                "dataset manifest must persist every document keyword count");
            require(
                manifest_text.find("\"frequency_min\":4") != std::string::npos &&
                    manifest_text.find("\"frequency_max\":4") != std::string::npos &&
                    manifest_text.find("\"frequency_mean\":4") != std::string::npos &&
                    manifest_text.find("\"frequency_stddev\":0") != std::string::npos,
                "dataset manifest must persist frequency summary statistics");
        }

        const auto loaded = pir::common::load_dataset(
            data_path, manifest_path, fingerprint);
        require(loaded.dataset == dataset, "dataset round trip changed bytes");
        require(loaded.manifest == saved_manifest, "manifest round trip changed fields");

        bool rejected = false;
        try
        {
            (void)pir::common::load_dataset(data_path, manifest_path, "wrong-fingerprint");
        }
        catch (const std::runtime_error &)
        {
            rejected = true;
        }
        require(rejected, "parameter fingerprint mismatch must be rejected");

        {
            std::fstream stream(data_path, std::ios::binary | std::ios::in | std::ios::out);
            stream.seekp(24);
            const char corruption = static_cast<char>(0xa5);
            stream.write(&corruption, 1);
        }
        rejected = false;
        try
        {
            (void)pir::common::load_dataset(data_path, manifest_path, fingerprint);
        }
        catch (const std::runtime_error &)
        {
            rejected = true;
        }
        require(rejected, "corrupted dataset must fail its stored SHA-256");

        const pir::common::BfvParameters parameters;
        const auto context = pir::common::make_bfv_context(parameters, 16);
        seal::BatchEncoder encoder(*context);
        std::vector<std::uint64_t> slots(encoder.slot_count(), 0);
        slots[0] = 7;
        slots[17] = 19;
        seal::Plaintext plaintext;
        encoder.encode(slots, plaintext);
        const auto plaintext_path = temporary.path() / "plaintexts.pirplain";
        const auto bfv_fingerprint = pir::common::bfv_parameter_fingerprint(parameters);
        pir::common::save_plaintexts_atomic(
            plaintext_path,
            std::vector<seal::Plaintext>{plaintext},
            "dataset-sha-fixture",
            bfv_fingerprint);
        const auto restored = pir::common::load_plaintexts(
            plaintext_path, *context, "dataset-sha-fixture", bfv_fingerprint);
        require(restored.size() == 1, "plaintext count changed");
        std::vector<std::uint64_t> decoded;
        encoder.decode(restored.front(), decoded);
        require(decoded[0] == 7 && decoded[17] == 19, "plaintext slots changed");

        auto incompatible = parameters;
        incompatible.block_count = 2;
        rejected = false;
        try
        {
            (void)pir::common::load_plaintexts(
                plaintext_path,
                *context,
                "dataset-sha-fixture",
                pir::common::bfv_parameter_fingerprint(incompatible));
        }
        catch (const std::runtime_error &)
        {
            rejected = true;
        }
        require(rejected, "plaintext parameter mismatch must be rejected");

        for (const auto &entry : std::filesystem::directory_iterator(temporary.path()))
        {
            require(
                entry.path().extension() != ".tmp",
                "successful atomic writes must not leave temporary files");
        }

        std::cout << "persistence_test: PASS\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &error)
    {
        std::cerr << "persistence_test: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
