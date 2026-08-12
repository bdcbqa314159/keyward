#pragma once
#include "keyward/secret_store.hpp"

namespace keyward {

#if defined(_WIN32)
// Windows Credential Manager backend (Win32 Credential Management API): one
// CRED_TYPE_GENERIC item per secret, target name namespaced "keyward:<app>:<name>".
// DPAPI-backed — the OS encrypts at rest with a key bound to the user's logon.
// Only declared on Windows; the body compiles empty elsewhere.
class WindowsCredentialStore : public SecretStore {
 public:
  explicit WindowsCredentialStore(std::string app = "keyward");
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, const std::string& value) override;
  void remove(const std::string& name) override;
  std::string location() const override {
    return "Windows Credential Manager (app=" + app_ + ")";
  }

 private:
  std::string app_;
};
#endif

}  // namespace keyward
