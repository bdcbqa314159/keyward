#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace keyward {

// One named field of a credential record. Whether a field is sensitive (masked
// in the TUI, wiped in memory) lives in the schema, not here — the codec deals
// only in bytes.
struct Field {
  std::string name;
  std::string value;
  bool operator==(const Field&) const = default;
};

using Fields = std::vector<Field>;

// Serialize an ordered list of fields into one self-contained blob — the bytes
// stored as a single item in the OS credential manager. Round-trips exactly,
// preserves order, and is binary-safe (names and values may contain any byte,
// including '\0', '=', newlines).
std::string encode_fields(const Fields& fields);

// Parse a blob produced by encode_fields back into the fields. Returns
// std::nullopt if the blob is truncated or malformed — and never reads out of
// bounds on hostile input.
std::optional<Fields> decode_fields(std::string_view blob);

}  // namespace keyward
