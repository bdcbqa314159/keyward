#include "keyward/key_provider.hpp"

#include <utility>

#include "keyward/crypto_primitives.hpp"  // derive_key
#include "keyward/secure_memory.hpp"      // secure_zero

namespace keyward {

PassphraseKeyProvider::PassphraseKeyProvider(PassphraseSource source)
    : source_(std::move(source)) {}

std::optional<Secret> PassphraseKeyProvider::unlock(std::string_view salt,
                                                    std::string_view reason) {
  std::optional<std::string> passphrase = source_(reason);
  if (!passphrase) return std::nullopt;  // user cancelled
  // Move the passphrase into secure memory (no-swap, guard-paged) and wipe the
  // plain source copy immediately, so it isn't a swappable std::string during the
  // ~2.2 s Argon2 derivation. (The Argon2 work buffer itself is a documented
  // residual — secure-allocating ~100 MB is impractical.)
  Secret secure_pass(*passphrase);
  secure_zero(passphrase->data(), passphrase->size());
  return derive_key(secure_pass.view(), salt);
}

}  // namespace keyward
