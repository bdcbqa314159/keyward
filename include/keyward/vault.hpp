#pragma once
#include <memory>
#include <optional>
#include <string>

#include "keyward/default_store.hpp"  // defaultSecretStore
#include "keyward/record.hpp"         // encode_fields / decode_fields
#include "keyward/schema.hpp"         // to_fields / from_fields
#include "keyward/secret_store.hpp"   // SecretStore

namespace keyward {

// Typed credential store. Saves/loads a whole record as ONE item in the
// underlying SecretStore (OS keychain, or the file fallback), by composing the
// schema mapping (struct <-> Fields) with the record codec (Fields <-> bytes).
//
//   Vault vault{"myapp"};
//   vault.save("jira", JiraCredential{...});
//   auto jira = vault.load<JiraCredential>("jira");   // std::optional<JiraCredential>
class Vault {
 public:
  // Real use: the platform keychain (file fallback) namespaced by the app.
  explicit Vault(const std::string& app) : store_(defaultSecretStore(app)) {}
  // Inject a store — tests, or a custom backend.
  explicit Vault(std::unique_ptr<SecretStore> store) : store_(std::move(store)) {}

  bool has(const std::string& service) { return store_->get(service).has_value(); }
  void remove(const std::string& service) { store_->remove(service); }

  // ---- implement these (task 6) --------------------------------------------

  // Serialize `record` (schema -> Fields -> bytes) and store it under `service`.
  template <class T>
  void save(const std::string& service, const T& record) {
    Fields fields = to_fields(record);
    std::string blob = encode_fields(fields);
    store_->set(service, blob);
  }

  // Fetch `service` and deserialize (bytes -> Fields -> T). std::nullopt if the
  // service isn't present, or if the stored bytes don't parse into a T.
  template <class T>
  std::optional<T> load(const std::string& service) {
    std::optional<std::string> stored = store_->get(service);
    if (!stored) return std::nullopt;
    std::optional<Fields> fields = decode_fields(*stored);
    if (!fields) return std::nullopt;
    return from_fields<T>(*fields);
  }

 private:
  std::unique_ptr<SecretStore> store_;
};

}  // namespace keyward
