#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pir::common
{
    [[nodiscard]] std::vector<std::uint8_t> sha256(
        std::string_view domain,
        std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::string sha256_hex(
        std::string_view domain,
        std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::string sha256_file_hex(
        const std::filesystem::path &path);
}
