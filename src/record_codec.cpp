#include <cstdint>
#include <optional>

#include "keyward/record.hpp"

namespace keyward {

namespace {
void put_u32(std::string& out, uint32_t n) {
  out.push_back(static_cast<char>((n >> 24) & 0xFF));
  out.push_back(static_cast<char>((n >> 16) & 0xFF));
  out.push_back(static_cast<char>((n >> 8) & 0xFF));
  out.push_back(static_cast<char>((n) & 0xFF));
}

uint32_t get_u32(std::string_view blob, std::size_t i) {
  return (static_cast<uint32_t>(static_cast<unsigned char>(blob[i])) << 24) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 1])) << 16) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 2])) << 8) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 3])));
}

// The first byte of every encoded record. Bump on any wire-format change so old
// or foreign blobs are rejected up front rather than silently mis-parsed.
constexpr unsigned char kFormatVersion = 1;
}  // namespace

std::string encode_fields(const Fields& fields) {
  std::string out{};
  out.push_back(static_cast<char>(kFormatVersion));  // version byte first
  for (const Field& f : fields) {
    put_u32(out, f.name.size());
    out += f.name;
    put_u32(out, f.value.size());
    out += f.value;
  }
  return out;
}

std::optional<Fields> decode_fields(std::string_view blob) {
  // First byte is the format version; reject an empty or unrecognised blob.
  if (blob.empty() || static_cast<unsigned char>(blob[0]) != kFormatVersion) return std::nullopt;

  Fields out;
  std::size_t i{1};  // start after the version byte
  while (i < blob.size()) {
    if (blob.size() - i < 4) return std::nullopt;
    uint32_t name_len = get_u32(blob, i);
    i += 4;
    if (blob.size() - i < name_len) return std::nullopt;
    std::string name(blob.substr(i, name_len));
    i += name_len;

    if (blob.size() - i < 4) return std::nullopt;
    uint32_t value_len = get_u32(blob, i);
    i += 4;
    if (blob.size() - i < value_len) return std::nullopt;
    std::string value(blob.substr(i, value_len));
    i += value_len;

    out.push_back({std::move(name), std::move(value)});
  }
  return out;
}

}  // namespace keyward
