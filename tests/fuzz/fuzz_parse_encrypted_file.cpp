// libFuzzer harness for the encrypted file store's READ path. FileSecretStore
// parses fully attacker-controlled bytes (a stored file from a backup, disk
// image or sync folder) through parse_encrypted_file -> base64_decode, then
// aead_open on each entry's nonce+sealed split. fuzz_unseal exercises secret_box's
// one-shot framing (salt|nonce|mac|cipher), which NO production code uses; this
// harness covers the framing the file store actually reads. Key/salt are fixed —
// we're fuzzing the parse + AEAD bounds handling, not the KDF or the tag.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

#include "keyward/crypto_primitives.hpp"      // aead_open, derive_key, kNonceSize, Secret
#include "keyward/encrypted_file_format.hpp"  // parse_encrypted_file, EncryptedFile

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::optional<keyward::EncryptedFile> ef =
      keyward::parse_encrypted_file(std::string_view(reinterpret_cast<const char*>(data), size));
  if (!ef) return 0;  // rejected at parse — the common fail-closed path

  // Parsed: drive aead_open's bounds handling on each entry's attacker-influenced
  // nonce+sealed split. Key derived once (cheap KDF under the fuzz build); AD is
  // omitted because we're probing memory safety, not the tag verdict.
  static const keyward::Secret key = keyward::derive_key("correct horse", "0123456789abcdef");
  for (const auto& [name, entry] : ef->entries) {
    (void)name;
    if (entry.size() < keyward::kNonceSize) continue;
    std::string_view nonce(entry.data(), keyward::kNonceSize);
    std::string_view sealed(entry.data() + keyward::kNonceSize, entry.size() - keyward::kNonceSize);
    (void)keyward::aead_open(key, nonce, sealed);
  }
  return 0;
}
