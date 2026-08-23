#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace keyward {

// Standard base64 (RFC 4648), used to make byte-arbitrary values survive the
// line-based file stores. One shared implementation so there is a single
// strict decoder to audit.

// Encode arbitrary bytes to base64 (with '=' padding).
std::string base64_encode(std::string_view in);

// Decode base64. Strict: length must be a multiple of 4, only the last group may
// pad, non-alphabet bytes are rejected — a fail-closed property, so garbage
// returns std::nullopt rather than partial output.
std::optional<std::string> base64_decode(std::string_view in);

}  // namespace keyward
