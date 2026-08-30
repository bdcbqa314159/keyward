// defaultStorePath + the two overloads of defaultSecretStore. Where an OS vault
// exists (macOS/Windows/Linux+libsecret — the CI platforms) the vault is the
// SOLE store and the key source is ignored: there is no file fallback behind it.
// The key source only matters on a no-vault platform, where it encrypts the file
// tier (proven by file_store_encryption_tests). Here we test the parts that are
// safe and pure in normal CI: that construction succeeds and stays vault-only.
#include "keyward/default_store.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <optional>
#include <string>

#include "keyward/key_provider.hpp"

namespace {
void setEnv(const char* k, const char* v) {
#if defined(_WIN32)
  _putenv_s(k, v);
#else
  setenv(k, v, 1);
#endif
}
void unsetEnv(const char* k) {
#if defined(_WIN32)
  _putenv_s(k, "");
#else
  unsetenv(k);
#endif
}
}  // namespace

TEST(DefaultStore, PathIsNamespacedToApp) {
  const auto p = keyward::defaultStorePath("kw-app-xyz");
  EXPECT_EQ(p.filename(), "credentials");
  EXPECT_NE(p.string().find("kw-app-xyz"), std::string::npos);
}

TEST(DefaultStore, EncryptingOverloadConstructs) {
  // A key source that would only be consulted on a store operation — construction
  // itself must not touch it. Just verify the overload builds a usable store
  // object (no set/get here: that would hit the real OS backend / home path).
  auto provider = std::make_unique<keyward::PassphraseKeyProvider>(
      [](std::string_view) -> std::optional<std::string> { return "pw"; });
  auto store = keyward::defaultSecretStore("kw-app-xyz", std::move(provider));
  ASSERT_NE(store, nullptr);
  EXPECT_FALSE(store->location().empty());
}

TEST(DefaultStore, NullKeySourceEqualsPlaintextOverload) {
  auto a = keyward::defaultSecretStore("kw-app-xyz");
  auto b = keyward::defaultSecretStore("kw-app-xyz", nullptr);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  EXPECT_EQ(a->location(), b->location());  // same store, same tier
}

// The KEYWARD_PASSPHRASE on-ramp constructs cleanly. On a no-vault platform this
// reaches the encrypted file tier (env -> provider -> encrypt); on a vault
// platform (the CI runners) the vault is returned and the env is simply ignored.
// Either way construction succeeds and touches no backend. Silence the sole-tier
// plaintext warning so the no-vault case doesn't print during the test.
TEST(DefaultStore, EnvPassphraseOnRampConstructs) {
  setEnv("KEYWARD_SILENCE_PLAINTEXT_WARNING", "1");
  setEnv("KEYWARD_PASSPHRASE", "deployment-secret");
  auto store = keyward::defaultSecretStore("kw-app-env");
  ASSERT_NE(store, nullptr);
  EXPECT_FALSE(store->location().empty());
  unsetEnv("KEYWARD_PASSPHRASE");
  unsetEnv("KEYWARD_SILENCE_PLAINTEXT_WARNING");
}
