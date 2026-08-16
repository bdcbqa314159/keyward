#pragma once
#include <string>
#include <vector>

#include "keyward/secret_store.hpp"

namespace keyward {

// The guard is deliberately TWO conditions, unlike the macOS/Windows backends.
// Security.framework and Advapi32 ship with their OS, so `__APPLE__` / `_WIN32`
// alone prove the API is there. libsecret does NOT ship with Linux — it is an
// optional system package (pkg-config `libsecret-1`). KEYWARD_HAVE_LIBSECRET is
// defined by CMake only when it was actually found, so a clone on a box without
// libsecret-1-dev still builds and falls through to the 0600 file store.
#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)
// Linux Secret Service backend (freedesktop.org Secret Service API, reached via
// libsecret): one stored item per secret, attributed "keyward:<app>:<name>".
// The provider is the user's keyring daemon (gnome-keyring, KWallet, KeePassXC
// with Secret Service enabled) — it encrypts at rest with a key derived from the
// login password, so we don't roll crypto. Only declared when libsecret is
// present; the body compiles empty otherwise.
class SecretServiceStore : public SecretStore {
 public:
  explicit SecretServiceStore(std::string app = "keyward");
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, const std::string& value) override;
  void remove(const std::string& name) override;
  std::vector<std::string> list() override;
  std::string location() const override { return "Linux Secret Service (app=" + app_ + ")"; }

 private:
  std::string app_;
};
#endif

}  // namespace keyward
