#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace keyward {

// Passphrase-based authenticated encryption for a small secret (a credential
// blob). The output of seal() is self-contained — it carries its own salt and
// nonce — so it is safe to write straight to a 0600 file and read back later.
//
// Implemented in src/secret_box.cpp with the vendored Monocypher: Argon2 to
// stretch the passphrase into a key, XChaCha20-Poly1305 to encrypt+authenticate.

// Encrypt `plaintext` under `passphrase`. Returns a fresh blob every call
// (random salt + nonce), even for identical inputs.
std::string seal(std::string_view plaintext, std::string_view passphrase);

// Decrypt a blob produced by seal(). Returns the plaintext, or std::nullopt if
// the passphrase is wrong, the blob was tampered with, or it is malformed /
// truncated. Never throws on bad input; wrong input is a nullopt, not an
// exception.
std::optional<std::string> unseal(std::string_view blob, std::string_view passphrase);

}  // namespace keyward
