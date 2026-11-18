#pragma once

#include "pir/common/dataset.hpp"
#include "pir/common/types.hpp"
#include "pir/pmkpir/query_compiler.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace pir::pmkpir
{
    class WideKeywordCodebook;

    struct Metrics
    {
        pir::common::HomomorphicCounters scan_operations;
        pir::common::HomomorphicCounters boolean_operations;
        double keyword_match_ms = 0;
        double boolean_evaluation_ms = 0;
    };

    struct SetupMetrics
    {
        double keyword_encode_ms = 0;
        double bitmap_build_ms = 0;
    };

    struct EncryptedQuery
    {
        std::vector<seal::Ciphertext> ciphertexts;
        CompiledQuery compiled;
        std::size_t serialized_size_bytes = 0;
        double serialization_ms = 0;
    };

    class PreprocessedDatabase
    {
    public:
        [[nodiscard]] std::size_t keyword_count() const noexcept;
        [[nodiscard]] std::size_t document_count() const noexcept;
        [[nodiscard]] std::size_t fragment_count() const noexcept;
        [[nodiscard]] const SetupMetrics &setup_metrics() const noexcept;

    private:
        friend class Server;
        std::size_t keyword_count_ = 0;
        std::size_t document_count_ = 0;
        std::size_t fragment_count_ = 0;
        SetupMetrics setup_metrics_;
        std::vector<seal::Plaintext> keyword_codes_;
        std::vector<seal::Plaintext> normalized_bitmap_fragments_;
    };

    struct EncryptedSelection
    {
        std::vector<seal::Ciphertext> fragments;
        Metrics metrics;
        std::size_t serialized_size_bytes = 0;
        double serialization_ms = 0;
    };

    struct DecryptedSelection
    {
        std::vector<std::uint8_t> bitmap;
        int minimum_noise_budget_bits = 0;
    };

    class Client
    {
    public:
        explicit Client(
            pir::common::BfvParameters parameters = {},
            std::size_t public_domain_bits = 16);
        ~Client();
        Client(Client &&) noexcept;
        Client &operator=(Client &&) noexcept;
        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        [[nodiscard]] std::shared_ptr<seal::SEALContext> context() const noexcept;
        [[nodiscard]] const seal::RelinKeys &relinearization_keys() const noexcept;
        [[nodiscard]] const seal::GaloisKeys &galois_keys() const noexcept;
        [[nodiscard]] EncryptedQuery create_query(const CompiledQuery &compiled) const;
        [[nodiscard]] EncryptedQuery create_query(
            const CompiledQuery &compiled,
            const WideKeywordCodebook &codebook) const;
        [[nodiscard]] DecryptedSelection decrypt_selection(
            const EncryptedSelection &selection,
            std::size_t document_count) const;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    class Server
    {
    public:
        Server(
            pir::common::BfvParameters parameters,
            std::shared_ptr<seal::SEALContext> context,
            seal::RelinKeys relinearization_keys,
            seal::GaloisKeys galois_keys);
        ~Server();
        Server(Server &&) noexcept;
        Server &operator=(Server &&) noexcept;
        Server(const Server &) = delete;
        Server &operator=(const Server &) = delete;

        [[nodiscard]] PreprocessedDatabase preprocess(
            const pir::common::Dataset &dataset) const;
        [[nodiscard]] PreprocessedDatabase preprocess(
            const pir::common::Dataset &dataset,
            const WideKeywordCodebook &codebook) const;
        void save_preprocessed(
            const PreprocessedDatabase &database,
            const std::filesystem::path &path,
            const std::string &dataset_sha256) const;
        [[nodiscard]] PreprocessedDatabase load_preprocessed(
            const std::filesystem::path &path,
            const std::string &dataset_sha256,
            std::size_t keyword_count,
            std::size_t document_count) const;
        [[nodiscard]] EncryptedSelection evaluate(
            const EncryptedQuery &query,
            const PreprocessedDatabase &database) const;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}
