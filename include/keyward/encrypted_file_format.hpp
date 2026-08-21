#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace keyward {

// On-disk layout for the encrypted file store (format only — no crypto, no I/O):
//
//   keyward-file-v1
//   salt=<base64 of the raw key-derivation salt>
//   <name>=<base64 of the raw sealed entry bytes>
//   ...
//
// Entry values are opaque here — the store puts nonce‖mac‖ciphertext in them; the
// format is agnostic to what's inside. base64 lets arbitrary bytes survive the
// line-based file. Names stay in the clear (consistent with Secret Service
// attributes), so list()/remove() work without the key.

struct EncryptedFile {
  std::string salt;                                          // raw bytes
  std::vector<std::pair<std::string, std::string>> entries;  // name -> raw sealed bytes
};

// Does `text` begin with the v1 magic line? A file that does NOT is a legacy
// plaintext file (or empty). The store uses this to decide before parsing —
// which keeps the fail-closed choice (accept legacy vs reject) at the store, not
// buried in the parser.
bool is_encrypted_file(std::string_view text);

// Serialize to the on-disk text above (base64-encoding salt and entry values).
std::string format_encrypted_file(const EncryptedFile& file);

// Parse a v1 encrypted file. std::nullopt if it lacks the magic line or is
// malformed in any way (bad base64, a non-blank line without '='), so a tampered
// or truncated encrypted file fails closed rather than parsing partially.
std::optional<EncryptedFile> parse_encrypted_file(std::string_view text);

}  // namespace keyward
