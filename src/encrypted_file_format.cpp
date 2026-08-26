#include "keyward/encrypted_file_format.hpp"

#include <cstddef>

#include "keyward/base64.hpp"

namespace keyward {
namespace {

constexpr std::string_view kMagic = "keyward-file-v2";
constexpr std::string_view kSaltKey = "salt=";

// One line without its terminator; strips a trailing '\r' so CRLF files parse.
std::string_view next_line(std::string_view& rest) {
  const std::size_t nl = rest.find('\n');
  std::string_view line = (nl == std::string_view::npos) ? rest : rest.substr(0, nl);
  rest = (nl == std::string_view::npos) ? std::string_view{} : rest.substr(nl + 1);
  if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
  return line;
}

}  // namespace

bool is_encrypted_file(std::string_view text) {
  std::string_view rest = text;
  return next_line(rest) == kMagic;
}

std::string format_encrypted_file(const EncryptedFile& file) {
  std::string out;
  out.append(kMagic).push_back('\n');
  out.append(kSaltKey).append(base64_encode(file.salt)).push_back('\n');
  for (const auto& [name, value] : file.entries) {
    out.append(name).push_back('=');
    out.append(base64_encode(value)).push_back('\n');
  }
  return out;
}

std::optional<EncryptedFile> parse_encrypted_file(std::string_view text) {
  std::string_view rest = text;
  if (next_line(rest) != kMagic) return std::nullopt;

  const std::string_view salt_line = next_line(rest);
  if (salt_line.substr(0, kSaltKey.size()) != kSaltKey) return std::nullopt;
  std::optional<std::string> salt = base64_decode(salt_line.substr(kSaltKey.size()));
  if (!salt) return std::nullopt;

  EncryptedFile file;
  file.salt = std::move(*salt);
  while (!rest.empty()) {
    const std::string_view line = next_line(rest);
    if (line.empty()) continue;  // tolerate blank/trailing lines
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) return std::nullopt;  // malformed -> fail closed
    std::optional<std::string> value = base64_decode(line.substr(eq + 1));
    if (!value) return std::nullopt;
    file.entries.emplace_back(std::string(line.substr(0, eq)), std::move(*value));
  }
  return file;
}

}  // namespace keyward
