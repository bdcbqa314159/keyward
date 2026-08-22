#include "keyward/default_store.hpp"

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <utility>

#include "keyward/fallback_secret_store.hpp"
#include "keyward/file_secret_store.hpp"
#include "keyward/keychain_secret_store.hpp"
#include "keyward/secret_service_store.hpp"
#include "keyward/windows_credential_store.hpp"

namespace fs = std::filesystem;

namespace keyward {
namespace {

constexpr const char* kPassphraseEnv = "KEYWARD_PASSPHRASE";
constexpr const char* kSilenceEnv = "KEYWARD_SILENCE_PLAINTEXT_WARNING";

// Headless on-ramp: if KEYWARD_PASSPHRASE is set, derive the file key from it, so
// a deployment can encrypt the fallback with no interactive prompt. Empty/unset
// -> nullptr (plaintext, as before). An explicit KeyProvider always wins over
// this, because the two-arg overload never consults the env.
std::unique_ptr<KeyProvider> envKeyProvider() {
  const char* pass = std::getenv(kPassphraseEnv);
  if (pass == nullptr || *pass == '\0') return nullptr;
  std::string value(pass);
  return std::make_unique<PassphraseKeyProvider>(
      [value = std::move(value)](std::string_view) -> std::optional<std::string> { return value; });
}

fs::path homeBase() {
#if defined(_WIN32)
  if (const char* p = std::getenv("APPDATA")) return fs::path(p);
  if (const char* u = std::getenv("USERPROFILE")) return fs::path(u);
#else
  if (const char* h = std::getenv("HOME")) return fs::path(h);
#endif
  return fs::current_path();
}

// Build the file tier: encrypted when a key source is supplied, plaintext when
// not. Only called on platforms where the file store can actually hold secrets
// (not Windows), so [[maybe_unused]].
[[maybe_unused]] std::unique_ptr<SecretStore> makeFileStore(
    const std::string& app, std::unique_ptr<KeyProvider> key_source) {
  if (key_source)
    return std::make_unique<FileSecretStore>(defaultStorePath(app), std::move(key_source));
  return std::make_unique<FileSecretStore>(defaultStorePath(app));
}

// Discoverability: when the file store is the SOLE tier (no OS vault) and no key
// source was given, secrets land in plaintext — the weakest configuration. Say
// so, once, on stderr, unless silenced. (Not warned for the file tier behind a
// keychain, where new secrets go to the vault and the file only drains legacy.)
// Only called in the sole-tier branch, so [[maybe_unused]] elsewhere.
[[maybe_unused]] void warnPlaintextFileTier(const std::string& app) {
  if (std::getenv(kSilenceEnv) != nullptr) return;
  std::fprintf(stderr,
               "keyward: no OS keychain available - secrets will be stored in PLAINTEXT at %s. "
               "Set %s, or pass a KeyProvider to defaultSecretStore(), to encrypt at rest. "
               "(Set %s to silence.)\n",
               defaultStorePath(app).string().c_str(), kPassphraseEnv, kSilenceEnv);
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
  // Bare call: no explicit key source, so consult the KEYWARD_PASSPHRASE on-ramp.
  return defaultSecretStore(app, envKeyProvider());
}

std::unique_ptr<SecretStore> defaultSecretStore(const std::string& app,
                                                std::unique_ptr<KeyProvider> key_source) {
#if defined(__APPLE__)
  // Keychain (namespaced to `app`) in front; the file tier stays readable so an
  // existing secret still works and migrates to the Keychain on the next `set`.
  // The file tier encrypts if a key source was supplied.
  return std::make_unique<FallbackSecretStore>(std::make_unique<KeychainSecretStore>(app),
                                               makeFileStore(app, std::move(key_source)));
#elif defined(_WIN32)
  // Windows = Credential Manager ONLY — no file fallback. CredMan is itself
  // DPAPI-encrypted, OS-managed storage; a self-managed 0600 file on Windows is
  // just a read-only attribute, not a real ACL, so falling back to it would be a
  // silent downgrade. Fail closed instead (the backend throws on any error).
  // There is no file tier here, so the key source is unused.
  (void)key_source;
  return std::make_unique<WindowsCredentialStore>(app);
#elif defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)
  // The user's keyring (namespaced to `app`) in front, mirroring macOS; the file
  // tier stays readable so an existing secret still works and migrates to the
  // keyring on the next `set`. Unlike Windows we keep the fallback: a 0600 file
  // on Linux IS a real permission bit, so it's a degraded store, not a fake one.
  return std::make_unique<FallbackSecretStore>(std::make_unique<SecretServiceStore>(app),
                                               makeFileStore(app, std::move(key_source)));
#else
  // No native vault available (Linux without libsecret, BSD, anything else): the
  // file store is the SOLE tier, so encrypting it (if a key source is given) is
  // where it matters most. Plaintext here is the weakest rung — warn.
  if (!key_source) warnPlaintextFileTier(app);
  return makeFileStore(app, std::move(key_source));
#endif
}

}  // namespace keyward
