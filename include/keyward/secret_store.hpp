#pragma once
#include <optional>
#include <string>

namespace keyward {

// OS-agnostic secret storage. A backend keeps named secrets as opaque strings —
// the OS keychain where available (macOS Keychain, Windows Credential Manager,
// Linux Secret Service), else a 0600 file fallback.
class SecretStore {
 public:
  virtual ~SecretStore() = default;
  virtual std::optional<std::string> get(const std::string& name) = 0;
  virtual void set(const std::string& name, const std::string& value) = 0;
  virtual void remove(const std::string& name) = 0;
  // Human-readable location (a path or "macOS Keychain") for status output.
  virtual std::string location() const = 0;
};

}  // namespace keyward
