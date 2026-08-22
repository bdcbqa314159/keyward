#pragma once
#include <filesystem>
#include <memory>
#include <string>

#include "keyward/key_provider.hpp"
#include "keyward/secret_store.hpp"

namespace keyward {

// File-backed store path for an application namespace:
//   macOS/Linux : ~/.config/<app>/credentials
//   Windows     : %APPDATA%\<app>\credentials
std::filesystem::path defaultStorePath(const std::string& app);

// The best store for this platform, namespaced to `app`: the OS keychain in
// front of the 0600 file fallback, so an existing file secret migrates to the
// keychain on the next write. Falls back to the file alone where no keychain
// backend exists (Linux without libsecret, BSD, ...). NOTE: that fallback file
// is PLAINTEXT — see the overload below to encrypt it.
std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app);

// As above, but the file tier — whether it's the fallback behind a keychain or
// the sole store — encrypts at rest with the given key source (Argon2id +
// XChaCha20-Poly1305). Use this on platforms where the file store may hold
// secrets (no OS vault) and you don't want them in plaintext. The key source is
// unused where a native vault is the only tier (Windows). Passing nullptr is
// equivalent to the plaintext overload above.
std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app,
                                                std::unique_ptr<KeyProvider> key_source);

}  // namespace keyward
