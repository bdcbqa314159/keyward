#pragma once
#include <filesystem>
#include <string>
#include <vector>

#include "keyward/secret_store.hpp"

namespace keyward {

// Portable fallback: `NAME=value` lines in a single owner-only (0600) file, in a
// 0700 directory.
//
// SECURITY CEILING: values are stored in PLAINTEXT — 0600 is access control, not
// encryption. Anyone who can read the file (backup, disk image, same-user
// process) reads the secret. Real at-rest encryption (passphrase -> Argon2i ->
// XChaCha20-Poly1305, e.g. vendored Monocypher) is a planned upgrade. This store
// is the fallback when no OS keychain is available.
class FileSecretStore : public SecretStore {
 public:
  explicit FileSecretStore(std::filesystem::path path);
  std::optional<std::string> get(const std::string& name) override;
  void set(const std::string& name, const std::string& value) override;
  void remove(const std::string& name) override;
  std::vector<std::string> list() override;
  std::string location() const override { return path_.string(); }

 private:
  std::filesystem::path path_;
};

}  // namespace keyward
