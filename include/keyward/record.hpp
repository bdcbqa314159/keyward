#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "keyward/secure_string.hpp"

namespace keyward {

// One named field of a credential record. Whether a field is sensitive (masked
// in the TUI, wiped in memory) lives in the schema, not here — the codec deals
// only in bytes.
struct Field {
  std::string name;
  std::string value;
  bool operator==(const Field&) const = default;
};

// R3-3: a zeroing allocator on the backing store, not std::allocator. A Fields
// vector grown by push_back sheds its old backing block on each reallocation —
// and for a SHORT (SSO) field value the secret bytes live INSIDE the Field
// object, i.e. inside that backing block, so an end-of-life wipe_fields (which
// only reaches the live vector) leaves them in freed heap. Routing every block
// the vector releases through SecureAllocator::deallocate zeroes the shed blocks
// structurally — the same reason SecureString exists for the serialized blob.
// (Large heap-allocated values move with the Field rather than being shed here,
// and are wiped live before destruction.)
using Fields = std::vector<Field, SecureAllocator<Field>>;

// Serialize an ordered list of fields into one self-contained blob — the bytes
// stored as a single item in the OS credential manager. The blob begins with a
// 1-byte format version so it can evolve. Round-trips exactly, preserves order,
// and is binary-safe (names and values may contain any byte, incl. '\0', '=', '\n').
SecureString encode_fields(const Fields& fields);

// Parse a blob produced by encode_fields back into the fields. Returns
// std::nullopt if the version byte is unrecognised, or the blob is truncated or
// malformed — and never reads out of bounds on hostile input.
std::optional<Fields> decode_fields(std::string_view blob);

}  // namespace keyward
