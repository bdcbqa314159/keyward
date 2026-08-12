#include "keyward/default_store.hpp"

#include <cstdlib>
#include <utility>

#include "keyward/fallback_secret_store.hpp"
#include "keyward/file_secret_store.hpp"
#include "keyward/keychain_secret_store.hpp"
#include "keyward/windows_credential_store.hpp"

namespace fs = std::filesystem;

namespace keyward {
namespace {

fs::path homeBase() {
#if defined(_WIN32)
  if (const char* p = std::getenv("APPDATA")) return fs::path(p);
  if (const char* u = std::getenv("USERPROFILE")) return fs::path(u);
#else
  if (const char* h = std::getenv("HOME")) return fs::path(h);
#endif
  return fs::current_path();
}

}  // namespace

fs::path defaultStorePath(const std::string& app) {
#if defined(_WIN32)
  return homeBase() / app / "credentials";
#else
  return homeBase() / ".config" / app / "credentials";
#endif
}

std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app) {
#if defined(__APPLE__)
  // Keychain (namespaced to `app`) in front; the 0600 file stays readable so an
  // existing secret still works and migrates to the Keychain on the next `set`.
  return std::make_unique<FallbackSecretStore>(
      std::make_unique<KeychainSecretStore>(app),
      std::make_unique<FileSecretStore>(defaultStorePath(app)));
#elif defined(_WIN32)
  // Windows = Credential Manager ONLY — no file fallback. CredMan is itself
  // DPAPI-encrypted, OS-managed storage; a self-managed 0600 file on Windows is
  // just a read-only attribute, not a real ACL, so falling back to it would be a
  // silent downgrade. Fail closed instead (the backend throws on any error).
  return std::make_unique<WindowsCredentialStore>(app);
#else
  // TODO: Linux libsecret in front here; file store is the universal fallback.
  return std::make_unique<FileSecretStore>(defaultStorePath(app));
#endif
}

}  // namespace keyward
