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

// The best store for this platform, namespaced to `app`. Where an OS vault
// exists it is the SOLE store — Keychain (macOS), Credential Manager (Windows),
// or Secret Service (Linux with libsecret). There is deliberately NO file
// fallback behind the vault: a plaintext file behind it was an injection surface
// (an attacker with file-write could plant a credentials file that gets served
// for any key absent from the vault), so the vault stands alone. To read or
// migrate secrets left in a legacy file tier, construct a FileSecretStore
// explicitly.
//
// Only where NO OS vault exists (Linux without libsecret, BSD, ...) does this
// return a file store. That file is PLAINTEXT unless a key source is given; as a
// headless on-ramp, setting the KEYWARD_PASSPHRASE environment variable encrypts
// it (Argon2id + XChaCha20-Poly1305) with no interactive prompt. A plaintext
// sole tier prints a one-line stderr warning (silence: KEYWARD_SILENCE_PLAINTEXT_WARNING).
std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app);

// As above, but encrypts the file tier with the given key source when the file
// tier is in play (i.e. no OS vault). Where a native vault is the store, the key
// source is unused. Passing nullptr is equivalent to the one-arg overload.
std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app,
                                                std::unique_ptr<KeyProvider> key_source);

}  // namespace keyward
