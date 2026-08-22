// defaultStorePath + the encrypting overload of defaultSecretStore. The
// two-arg overload is thin wiring — it passes the KeyProvider to the file tier's
// encrypting constructor. That the file tier encrypts is proven by
// file_store_encryption_tests; that defaultSecretStore reaches it end-to-end is
// platform-dependent (keychain-fronted) and lives in the host-gated vault
// smokes. Here we test the parts that are safe and pure in normal CI.
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

// The KEYWARD_PASSPHRASE on-ramp path constructs cleanly (env -> provider ->
// encrypted file tier). Construction is backend-free; this exercises the env
// code path under the sanitizer/leak jobs. The encryption itself is proven in
// file_store_encryption_tests. Silence the sole-tier plaintext warning so the
// no-vault CI runners don't print during the test.
TEST(DefaultStore, EnvPassphraseOnRampConstructs) {
  setEnv("KEYWARD_SILENCE_PLAINTEXT_WARNING", "1");
  setEnv("KEYWARD_PASSPHRASE", "deployment-secret");
  auto store = keyward::defaultSecretStore("kw-app-env");
  ASSERT_NE(store, nullptr);
  EXPECT_FALSE(store->location().empty());
  unsetEnv("KEYWARD_PASSPHRASE");
  unsetEnv("KEYWARD_SILENCE_PLAINTEXT_WARNING");
}
