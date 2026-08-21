#include "keyward/encrypted_file_format.hpp"

#include <cstdint>

namespace keyward {
namespace {

constexpr std::string_view kMagic = "keyward-file-v1";
constexpr std::string_view kSaltKey = "salt=";
constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(std::string_view in) {
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  auto byte = [&](std::size_t i) {
    return static_cast<uint32_t>(static_cast<unsigned char>(in[i]));
  };
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    uint32_t n = (byte(i) << 16) | (byte(i + 1) << 8) | byte(i + 2);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back(kB64[n & 63]);
  }
  if (const std::size_t rem = in.size() - i; rem == 1) {
    uint32_t n = byte(i) << 16;
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.append("==");
  } else if (rem == 2) {
    uint32_t n = (byte(i) << 16) | (byte(i + 1) << 8);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

int b64_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Strict base64: length must be a multiple of 4, only the last group may pad,
// non-alphabet bytes are rejected. Rejecting garbage is a fail-closed property.
std::optional<std::string> b64_decode(std::string_view in) {
  if (in.size() % 4 != 0) return std::nullopt;
  std::string out;
  out.reserve(in.size() / 4 * 3);
  for (std::size_t i = 0; i < in.size(); i += 4) {
    const int a = b64_val(in[i]);
    const int b = b64_val(in[i + 1]);
    if (a < 0 || b < 0) return std::nullopt;
    const char c3 = in[i + 2];
    const char c4 = in[i + 3];
    uint32_t n = (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12);
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    if (c3 == '=') {
      if (c4 != '=' || i + 4 != in.size()) return std::nullopt;  // padding only at the very end
    } else {
      const int c = b64_val(c3);
      if (c < 0) return std::nullopt;
      n |= static_cast<uint32_t>(c) << 6;
      out.push_back(static_cast<char>((n >> 8) & 0xFF));
      if (c4 == '=') {
        if (i + 4 != in.size()) return std::nullopt;
      } else {
        const int d = b64_val(c4);
        if (d < 0) return std::nullopt;
        n |= static_cast<uint32_t>(d);
        out.push_back(static_cast<char>(n & 0xFF));
      }
    }
  }
  return out;
}

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
  out.append(kSaltKey).append(b64_encode(file.salt)).push_back('\n');
  for (const auto& [name, value] : file.entries) {
    out.append(name).push_back('=');
    out.append(b64_encode(value)).push_back('\n');
  }
  return out;
}

std::optional<EncryptedFile> parse_encrypted_file(std::string_view text) {
  std::string_view rest = text;
  if (next_line(rest) != kMagic) return std::nullopt;

  const std::string_view salt_line = next_line(rest);
  if (salt_line.substr(0, kSaltKey.size()) != kSaltKey) return std::nullopt;
  std::optional<std::string> salt = b64_decode(salt_line.substr(kSaltKey.size()));
  if (!salt) return std::nullopt;

  EncryptedFile file;
  file.salt = std::move(*salt);
  while (!rest.empty()) {
    const std::string_view line = next_line(rest);
    if (line.empty()) continue;  // tolerate blank/trailing lines
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) return std::nullopt;  // malformed -> fail closed
    std::optional<std::string> value = b64_decode(line.substr(eq + 1));
    if (!value) return std::nullopt;
    file.entries.emplace_back(std::string(line.substr(0, eq)), std::move(*value));
  }
  return file;
}

}  // namespace keyward
