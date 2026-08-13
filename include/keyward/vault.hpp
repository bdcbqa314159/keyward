#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "keyward/default_store.hpp"  // defaultSecretStore
#include "keyward/prompter.hpp"       // Prompter / PromptReason / PromptField
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

  // Names of all stored services (for a listing / picker UI). Throws if the
  // underlying backend can't enumerate (see SecretStore::list).
  std::vector<std::string> list() { return store_->list(); }

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

  // Present & valid -> load it. Otherwise prompt the user to create it, save,
  // and return. std::nullopt if the user cancels. A stored-but-unparseable
  // record is treated as a re-entry (Corrupt) prompt.
  template <class T>
  std::optional<T> ensure(const std::string& service, Prompter& prompter) {
    PromptReason reason = PromptReason::Missing;
    if (has(service)) {
      if (std::optional<T> current = load<T>(service)) return current;  // present & valid
      reason = PromptReason::Corrupt;                                   // present but garbage
    }
    return prompt_and_save<T>(service, prompter, reason, /*prefill=*/nullptr);
  }

  // Force a pre-filled UPDATE prompt — call this when *your* service rejected the
  // stored credential (only the app knows a loaded record is invalid). Current
  // values pre-fill the form so the user edits rather than retypes. std::nullopt
  // if the user cancels.
  template <class T>
  std::optional<T> revise(const std::string& service, Prompter& prompter) {
    std::optional<T> current = load<T>(service);
    return prompt_and_save<T>(service, prompter, PromptReason::Invalid,
                              current ? &*current : nullptr);
  }

 private:
  // Build prompt fields from T's schema (name + Sensitive flag, optionally
  // pre-filled), run the prompter, and on confirmation rebuild + save the
  // record. Shared by ensure/revise.
  template <class T>
  std::optional<T> prompt_and_save(const std::string& service, Prompter& prompter,
                                   PromptReason reason, const T* prefill) {
    std::vector<PromptField> fields;
    for (const auto& spec : T::schema()) {
      fields.push_back({spec.name, spec.sensitivity == Sensitivity::Sensitive,
                        prefill ? prefill->*(spec.member) : std::string{}});
    }
    if (!prompter.collect(service, reason, fields)) return std::nullopt;  // cancelled

    Fields collected;
    for (const PromptField& f : fields) collected.push_back({f.name, f.value});
    std::optional<T> record = from_fields<T>(collected);
    if (!record) return std::nullopt;  // prompter returned an incomplete set

    save<T>(service, *record);
    return record;
  }

  std::unique_ptr<SecretStore> store_;
};

}  // namespace keyward
