#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "keyward/authenticator.hpp"  // Authenticator / Authorization / NoAuth
#include "keyward/default_store.hpp"  // defaultSecretStore
#include "keyward/prompter.hpp"       // Prompter / PromptReason / PromptField
#include "keyward/record.hpp"         // encode_fields / decode_fields
#include "keyward/schema.hpp"         // to_fields / from_fields
#include "keyward/secret_store.hpp"   // SecretStore
#include "keyward/secure_memory.hpp"  // secure_zero

namespace keyward {

// Typed credential store. Saves/loads a whole record as ONE item in the
// underlying SecretStore (OS keychain, or the file fallback), by composing the
// schema mapping (struct <-> Fields) with the record codec (Fields <-> bytes).
//
// An optional Authenticator gates read access (defaults to NoAuth = today's
// behaviour); load/ensure/revise consult it before releasing a secret.
//
//   Vault vault{"myapp"};
//   vault.save("jira", JiraCredential{...});
//   auto jira = vault.load<JiraCredential>("jira");   // std::optional<JiraCredential>
class Vault {
 public:
  // Real use: the platform keychain (file fallback) namespaced by the app.
  explicit Vault(const std::string& app,
                 std::unique_ptr<Authenticator> auth = std::make_unique<NoAuth>())
      : store_(defaultSecretStore(app)), auth_(std::move(auth)) {}
  // Inject a store — tests, or a custom backend.
  explicit Vault(std::unique_ptr<SecretStore> store,
                 std::unique_ptr<Authenticator> auth = std::make_unique<NoAuth>())
      : store_(std::move(store)), auth_(std::move(auth)) {}

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
    secure_zero(blob.data(), blob.size());  // don't leave the serialized secret in freed heap
    wipe_fields(fields);
  }

  // Authorize, then fetch `service` and deserialize (bytes -> Fields -> T).
  // std::nullopt if access is denied, the service isn't present, or the stored
  // bytes don't parse into a T.
  template <class T>
  std::optional<T> load(const std::string& service) {
    if (auth_->authorize(service, "read") != Authorization::Allowed) return std::nullopt;
    return load_stored<T>(service);
  }

  // Present -> authorize and load it. Absent -> prompt to create it, save, and
  // return. std::nullopt if access is denied or the user cancels. A stored-but-
  // unparseable record is treated as a re-entry (Corrupt) prompt.
  template <class T>
  std::optional<T> ensure(const std::string& service, Prompter& prompter) {
    if (has(service)) {
      // Present but access denied — fail closed; do NOT fall through to a prompt.
      if (auth_->authorize(service, "read") != Authorization::Allowed) return std::nullopt;
      if (std::optional<T> current = load_stored<T>(service)) return current;  // present & valid
      return prompt_and_save<T>(service, prompter, PromptReason::Corrupt, /*prefill=*/nullptr);
    }
    return prompt_and_save<T>(service, prompter, PromptReason::Missing, /*prefill=*/nullptr);
  }

  // Force a pre-filled UPDATE prompt — call this when *your* service rejected the
  // stored credential (only the app knows a loaded record is invalid). Current
  // values pre-fill the form (only if access is authorized) so the user edits
  // rather than retypes. std::nullopt if the user cancels.
  template <class T>
  std::optional<T> revise(const std::string& service, Prompter& prompter) {
    std::optional<T> current;
    if (auth_->authorize(service, "read") == Authorization::Allowed)
      current = load_stored<T>(service);
    return prompt_and_save<T>(service, prompter, PromptReason::Invalid,
                              current ? &*current : nullptr);
  }

 private:
  // Overwrite the plaintext values of a decoded/gathered Fields list so they
  // don't linger in freed heap. Names aren't secret, so only values are wiped.
  static void wipe_fields(Fields& fields) {
    for (Field& f : fields) secure_zero(f.value.data(), f.value.size());
  }

  // The un-gated core of load — fetch + decode + typed rebuild. Callers gate.
  // The transient plaintext (the raw blob, the decoded Fields) is wiped once the
  // typed record is built; the returned record is the caller's to hold.
  template <class T>
  std::optional<T> load_stored(const std::string& service) {
    std::optional<std::string> stored = store_->get(service);
    if (!stored) return std::nullopt;
    std::optional<Fields> fields = decode_fields(*stored);
    secure_zero(stored->data(), stored->size());  // raw blob copy
    if (!fields) return std::nullopt;
    std::optional<T> record = from_fields<T>(*fields);
    wipe_fields(*fields);  // decoded plaintext transients
    return record;
  }

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

    // Wipe the gathered/serialized plaintext transients (the record is the
    // caller's to hold; save() wipes its own copies).
    wipe_fields(collected);
    for (PromptField& f : fields) secure_zero(f.value.data(), f.value.size());

    if (!record) return std::nullopt;  // prompter returned an incomplete set
    save<T>(service, *record);
    return record;
  }

  std::unique_ptr<SecretStore> store_;
  std::unique_ptr<Authenticator> auth_;
};

}  // namespace keyward
