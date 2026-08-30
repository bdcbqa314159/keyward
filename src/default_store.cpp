#include "keyward/default_store.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "keyward/file_secret_store.hpp"
#include "keyward/key_provider.hpp"  // PassphraseKeyProvider, KeyProvider
#include "keyward/keychain_secret_store.hpp"
#include "keyward/secret.hpp"  // Secret (secure-memory hold for L1)
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
  // L1: keep the passphrase in secure memory for the store's lifetime, not a
  // long-lived plaintext std::string. shared_ptr because PassphraseSource is a
  // std::function (copyable); Secret is move-only. Each call materializes a
  // transient std::string the consumer wipes after derive — the same residual
  // the interactive path already accepts.
  auto held = std::make_shared<Secret>(std::string_view(pass));
  // R3-8: now that the passphrase lives in secure memory (held), best-effort
  // remove it from the process environment so it isn't inherited by child
  // processes or readable via /proc/<pid>/environ for the process lifetime. `pass`
  // must not be used after this (unsetenv may invalidate it) — it isn't.
#if defined(_WIN32)
  _putenv_s(kPassphraseEnv, "");
#else
  ::unsetenv(kPassphraseEnv);
#endif
  return std::make_unique<PassphraseKeyProvider>(
      [held](std::string_view) -> std::optional<std::string> { return std::string(held->view()); });
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
  // Keychain (namespaced to `app`) ONLY — no file fallback. A plaintext file
  // behind the vault was an injection surface (an attacker with file-write plants
  // a credentials file and it's served for any key absent from the Keychain), and
  // even an encrypted fallback only ever drained legacy secrets that evict on the
  // first write. The vault is the store. No file tier here, so the key source is
  // unused. Existing file-tier secrets: construct a FileSecretStore explicitly to
  // read/migrate them.
  (void)key_source;
  return std::make_unique<KeychainSecretStore>(app);
#elif defined(_WIN32)
  // Windows = Credential Manager ONLY — no file fallback. CredMan is itself
  // DPAPI-encrypted, OS-managed storage; a self-managed 0600 file on Windows is
  // just a read-only attribute, not a real ACL, so falling back to it would be a
  // silent downgrade. Fail closed instead (the backend throws on any error).
  // There is no file tier here, so the key source is unused.
  (void)key_source;
  return std::make_unique<WindowsCredentialStore>(app);
#elif defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)
  // The user's keyring (namespaced to `app`) ONLY, mirroring macOS — no file
  // fallback, for the same reason: a plaintext file behind the vault is an
  // injection surface, and the fallback's only jobs (drain-legacy, degraded
  // store) don't justify it when the keyring works. Key source unused.
  (void)key_source;
  return std::make_unique<SecretServiceStore>(app);
#else
  // No native vault available (Linux without libsecret, BSD, anything else): the
  // file store is the SOLE tier, so encrypting it (if a key source is given) is
  // where it matters most. Plaintext here is the weakest rung — warn.
  if (!key_source) warnPlaintextFileTier(app);
  return makeFileStore(app, std::move(key_source));
#endif
}

}  // namespace keyward
