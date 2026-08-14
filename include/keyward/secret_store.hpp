#pragma once
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

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

  // Names of every secret in this store (the keys you'd pass to get), not the
  // values. Powers listing / a picker UI (e.g. the TUI). NOT pure: a backend
  // that can't enumerate inherits this fail-loud default and THROWS, rather than
  // silently returning an incomplete list that would hide real credentials.
  virtual std::vector<std::string> list() {
    throw std::logic_error("keyward: list() is not supported by this SecretStore backend");
  }
};

}  // namespace keyward
