#pragma once
#include <optional>
#include <string>
#include <string_view>

#include "keyward/passphrase_authenticator.hpp"  // PassphraseSource
#include "keyward/secret.hpp"

namespace keyward {

// Where the encrypted file store's key comes from. Kept separate from
// Authenticator on purpose: an Authenticator answers "may this caller proceed?"
// (a verdict, no key material), while a KeyProvider produces the actual
// encryption key. See docs/FILE_ENCRYPTION.md (Decision 1).
class KeyProvider {
 public:
  virtual ~KeyProvider() = default;

  // Produce the 32-byte file key, or std::nullopt to cancel / when no key is
  // available. `salt` is the file's stored key-derivation salt (providers that
  // don't derive from a passphrase may ignore it); `reason` contextualises any
  // prompt shown to the user. The result lives in secure memory.
  virtual std::optional<Secret> unlock(std::string_view salt, std::string_view reason) = 0;
};

// A KeyProvider that derives the key from a passphrase (Argon2id, via
// derive_key) gathered through a PassphraseSource — the same masked-input
// callback the passphrase authenticator uses. Single-shot: a wrong passphrase
// yields a wrong key, which surfaces later as an AEAD failure (there is no
// verifier to check against here), so retry is the caller's concern.
class PassphraseKeyProvider : public KeyProvider {
 public:
  explicit PassphraseKeyProvider(PassphraseSource source);
  std::optional<Secret> unlock(std::string_view salt, std::string_view reason) override;

 private:
  PassphraseSource source_;
};

}  // namespace keyward
