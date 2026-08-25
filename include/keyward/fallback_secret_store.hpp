#pragma once
#include <memory>
#include <string>
#include <vector>

#include "keyward/secret_store.hpp"

namespace keyward {

// Composes two stores: reads try primary then fallback; a write goes to the
// primary and EVICTS any stale copy from the fallback (migration is moving, not
// copying); a remove hits both tiers; list() unions both. Lets a native keychain
// sit in front of the 0600 file so an existing file-stored secret stays readable
// and migrates on the next `set`. Both tiers must be non-null.
class FallbackSecretStore : public SecretStore {
 public:
  FallbackSecretStore(std::unique_ptr<SecretStore> primary, std::unique_ptr<SecretStore> fallback);
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, std::string_view value) override;
  void remove(const std::string& name) override;
  std::vector<std::string> list() override;
  std::string location() const override;

 private:
  std::unique_ptr<SecretStore> primary_, fallback_;
};

}  // namespace keyward
