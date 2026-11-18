#pragma once

#include "pir/common/dataset.hpp"
#include "pir/common/types.hpp"

#include <seal/seal.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pir::common
{
    struct CacheManifest
    {
        std::uint32_t format_version = 1;
        std::string kind;
        std::string parameter_fingerprint;
        std::string data_sha256;
        std::string seal_version;

        bool operator==(const CacheManifest &) const = default;
    };

    struct LoadedDataset
    {
        Dataset dataset;
        CacheManifest manifest;
    };

    [[nodiscard]] std::string bfv_parameter_fingerprint(
        const BfvParameters &parameters);

    [[nodiscard]] CacheManifest save_dataset_atomic(
        const std::filesystem::path &data_path,
        const std::filesystem::path &manifest_path,
        const Dataset &dataset,
        const std::string &parameter_fingerprint);

    [[nodiscard]] LoadedDataset load_dataset(
        const std::filesystem::path &data_path,
        const std::filesystem::path &manifest_path,
        const std::string &expected_parameter_fingerprint);

    void save_plaintexts_atomic(
        const std::filesystem::path &path,
        const std::vector<seal::Plaintext> &plaintexts,
        const std::string &dataset_sha256,
        const std::string &parameter_fingerprint);

    [[nodiscard]] std::vector<seal::Plaintext> load_plaintexts(
        const std::filesystem::path &path,
        const seal::SEALContext &context,
        const std::string &expected_dataset_sha256,
        const std::string &expected_parameter_fingerprint);
}
