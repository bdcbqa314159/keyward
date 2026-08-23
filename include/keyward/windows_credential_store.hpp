#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "keyward/secret_store.hpp"

namespace keyward {

#if defined(_WIN32)
// Windows Credential Manager backend (Win32 Credential Management API): one
// CRED_TYPE_GENERIC item per secret. Target/username naming follows Python
// `keyring`'s WinVaultKeyring so the two tools share a namespace: target
// "<name>@<app>", UserName "<name>" (keyring's "<username>@<service>"). DPAPI-
// backed — the OS encrypts at rest with a key bound to the user's logon. The blob
// is stored as RAW BYTES (binary-safe for Vault records); keyring stores UTF-16-LE
// text, so items are mutually discoverable but a value only crosses intact when it
// is UTF-16-LE (see the src note and docs/DESIGN.md). Only declared on Windows;
// the body compiles empty elsewhere.
class WindowsCredentialStore : public SecretStore {
 public:
  explicit WindowsCredentialStore(std::string app = "keyward");
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, std::string_view value) override;
  void remove(const std::string& name) override;
  std::vector<std::string> list() override;
  std::string location() const override { return "Windows Credential Manager (app=" + app_ + ")"; }

 private:
  std::string app_;
};
#endif

}  // namespace keyward
