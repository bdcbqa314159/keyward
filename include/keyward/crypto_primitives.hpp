#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include "keyward/secret.hpp"

// Low-level building blocks under seal()/unseal(). Split out so a caller can
// derive a key ONCE and reuse it across many AEAD operations with distinct
// nonces — e.g. the encrypted file store: one Argon2id per file (~2.2 s), then a
// cheap per-entry aead_seal/aead_open. seal()/unseal() are the one-shot
// convenience built on exactly these three calls.

namespace keyward {

inline constexpr std::size_t kKeySize = 32;    // XChaCha20-Poly1305 key
inline constexpr std::size_t kSaltSize = 16;   // Argon2id salt
inline constexpr std::size_t kNonceSize = 24;  // XChaCha20 nonce
inline constexpr std::size_t kMacSize = 16;    // Poly1305 tag

// Stretch a passphrase into a kKeySize-byte key with Argon2id and the given
// `salt` (kSaltSize bytes recommended). Deterministic: same passphrase + salt ->
// same key. Returned in secure memory (mlock'd, zeroed on drop). This is the
// expensive step (~2.2 s at production cost) — derive once, reuse the result.
Secret derive_key(std::string_view passphrase, std::string_view salt);

// AEAD-encrypt `plaintext` under `key` (kKeySize) and `nonce` (kNonceSize) with
// XChaCha20-Poly1305. Returns mac(kMacSize) || ciphertext (ciphertext is the
// same length as plaintext). The nonce MUST be unique per key — use a fresh
// random nonce per call, or a distinct nonce per entry under a shared key.
std::string aead_seal(const Secret& key, std::string_view nonce, std::string_view plaintext);

// Reverse aead_seal: `sealed` is mac || ciphertext. Returns the plaintext in
// secure memory, or std::nullopt if the key/nonce are wrong, the data was
// tampered with, or `sealed` is malformed (shorter than a MAC). Never throws.
std::optional<Secret> aead_open(const Secret& key, std::string_view nonce, std::string_view sealed);

}  // namespace keyward
