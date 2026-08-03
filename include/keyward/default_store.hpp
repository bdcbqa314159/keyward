#pragma once
#include <filesystem>
#include <memory>
#include <string>

#include "keyward/secret_store.hpp"

namespace keyward {

// File-backed store path for an application namespace:
//   macOS/Linux : ~/.config/<app>/credentials
//   Windows     : %APPDATA%\<app>\credentials
std::filesystem::path defaultStorePath(const std::string& app);

// The best store for this platform, namespaced to `app`: the OS keychain
// (macOS today) in front of the 0600 file fallback, so an existing file secret
// migrates to the keychain on the next write. Falls back to the file alone
// where no keychain backend exists yet.
std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app);

}  // namespace keyward
