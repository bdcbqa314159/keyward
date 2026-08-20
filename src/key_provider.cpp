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
  Secret key = derive_key(*passphrase, salt);
  secure_zero(passphrase->data(), passphrase->size());  // wipe the transient passphrase copy
  return key;
}

}  // namespace keyward
