#pragma once
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "keyward/key_provider.hpp"
#include "keyward/secret.hpp"
#include "keyward/secret_store.hpp"

namespace keyward {

// Portable fallback: one owner-only (0600) file in a 0700 directory.
//
// Two modes:
//  - Plaintext (the path-only constructor). `NAME=value` lines. SECURITY
//    CEILING: values are stored in PLAINTEXT — 0600 is access control, not
//    encryption. Anyone who can read the file reads the secret.
//  - Encrypted (constructed with a KeyProvider). Each value is sealed with
//    Argon2id + XChaCha20-Poly1305 (keyward-file-v1 format). The key is derived
//    once via the provider and cached for the store's lifetime. Names stay in
//    the clear, so list()/remove() work WITHOUT the key; get()/set() need it. A
//    legacy plaintext file is read as-is and migrated to encrypted on the next
//    set(); an undecryptable present entry throws (fails closed).
class FileSecretStore : public SecretStore {
 public:
  explicit FileSecretStore(std::filesystem::path path);
  FileSecretStore(std::filesystem::path path, std::unique_ptr<KeyProvider> key_provider);

  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, std::string_view value) override;
  void remove(const std::string& name) override;
  std::vector<std::string> list() override;
  std::string location() const override { return path_.string(); }

 private:
  bool encrypted() const { return key_provider_ != nullptr; }
  // Derive (once) and cache the key for `salt`; throws if the user cancels.
  const Secret& ensureKey(std::string_view salt);

  std::filesystem::path path_;
  std::unique_ptr<KeyProvider> key_provider_;  // null = plaintext mode
  std::optional<Secret> key_;                  // cached derived key (encryption mode)
  std::string salt_;                           // cached salt (matches the file header)
};

}  // namespace keyward
