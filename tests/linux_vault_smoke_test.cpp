// Host-gated end-to-end smoke test: drives the whole Vault facade
// (schema -> Fields -> bytes -> Secret Service and back) over the REAL Linux
// keyring. This is the layer the unit contract test doesn't reach: it proves the
// typed save/load<T> path works against the live OS vault, not just
// SecretServiceStore in isolation.
//
// Opt-in only: set KEYWARD_HOST_TESTS=1 to run. Otherwise it GTEST_SKIPs, so
// ordinary `ctest` and CI runs never write to a developer's real keyring. It
// uses a throwaway app namespace and removes what it writes. Without libsecret
// it is a single skip so the suite stays green cross-platform.
#include <gtest/gtest.h>

#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)

#include <cstdlib>
#include <memory>
#include <string>

#include "keyward/default_store.hpp"
#include "keyward/schema.hpp"
#include "keyward/secret_service_store.hpp"
#include "keyward/vault.hpp"

namespace {

bool hostTestsEnabled() {
  const char* v = std::getenv("KEYWARD_HOST_TESTS");
  return v != nullptr && std::string(v) == "1";
}

struct SmokeCred {
  std::string email;
  std::string url;
  std::string token;
  bool operator==(const SmokeCred&) const = default;

  static keyward::Schema<SmokeCred> schema() {
    return {
        {"email", &SmokeCred::email},
        {"url", &SmokeCred::url},
        {"token", &SmokeCred::token, keyward::Sensitive},
    };
  }
};

}  // namespace

TEST(LinuxVaultSmoke, RoundTripsThroughRealSecretService) {
  if (!hostTestsEnabled())
    GTEST_SKIP() << "host test: set KEYWARD_HOST_TESTS=1 to run against the real keyring";

  // Explicit backend, not defaultSecretStore — this test must exercise the
  // Secret Service even before defaultSecretStore is wired to prefer it (that
  // wiring has its own oracle below). Throwaway app namespace.
  keyward::Vault vault{std::make_unique<keyward::SecretServiceStore>("keyward-host-smoke")};
  const std::string service = "jira";
  vault.remove(service);  // clean slate
  EXPECT_FALSE(vault.has(service));

  const SmokeCred in{"a@b.com", "https://example.atlassian.net", "s3cr3t-token"};
  vault.save(service, in);

  ASSERT_TRUE(vault.has(service));
  auto out = vault.load<SmokeCred>(service);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);

  // Upsert through the facade, then confirm the new value round-trips.
  const SmokeCred revised{"c@d.com", "https://other.atlassian.net", "rotated-token"};
  vault.save(service, revised);
  auto after = vault.load<SmokeCred>(service);
  ASSERT_TRUE(after.has_value());
  EXPECT_EQ(*after, revised);

  vault.remove(service);  // cleanup — leave the keyring as we found it
  EXPECT_FALSE(vault.has(service));
}

// Oracle for the STRETCH: once defaultSecretStore prefers the Secret Service on
// Linux, a plain `Vault{app}` reaches the real keyring instead of the plaintext
// 0600 file. Red until src/default_store.cpp is wired. Needs no keyring access
// (it only inspects location()), so it is not host-gated.
TEST(LinuxVaultSmoke, DefaultStorePrefersSecretService) {
  auto store = keyward::defaultSecretStore("keyward-host-smoke");
  EXPECT_NE(store->location().find("Secret Service"), std::string::npos)
      << "defaultSecretStore returned: " << store->location();
}

#else  // no libsecret

TEST(LinuxVaultSmoke, SkippedWithoutLibsecret) {
  GTEST_SKIP() << "Linux Secret Service backend not built (needs pkg-config libsecret-1)";
}

#endif
