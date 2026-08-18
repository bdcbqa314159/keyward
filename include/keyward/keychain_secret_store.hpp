#pragma once
#include "keyward/secret_store.hpp"

namespace keyward {

#if defined(__APPLE__)
// macOS Keychain backend (Security.framework): generic-password items keyed by
// (service, account), one per secret name. The service namespaces an app's
// secrets. Only declared on Apple platforms.
class KeychainSecretStore : public SecretStore {
 public:
  explicit KeychainSecretStore(std::string service = "keyward");
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, std::string_view value) override;
  void remove(const std::string& name) override;
  std::string location() const override { return "macOS Keychain (service=" + service_ + ")"; }

 private:
  std::string service_;
};
#endif

}  // namespace keyward
