// Host-gated end-to-end smoke test: drives the whole Vault facade
// (schema -> Fields -> bytes -> CredWrite and back) over the REAL Windows
// Credential Manager, via defaultSecretStore. This is the layer the unit
// contract test doesn't reach: it proves the typed save/load<T> path works
// against the live OS vault, not just WindowsCredentialStore in isolation.
//
// Opt-in only: set KEYWARD_HOST_TESTS=1 to run. Otherwise it GTEST_SKIPs, so
// ordinary `ctest` and CI runs never write to a developer's real vault. It uses
// a throwaway app namespace and removes what it writes. Off Windows it is a
// single skip so the suite stays green cross-platform.
#include <gtest/gtest.h>

#if defined(_WIN32)

#include <cstdlib>
#include <string>

#include "keyward/schema.hpp"
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

TEST(WindowsVaultSmoke, RoundTripsThroughRealCredentialManager) {
  if (!hostTestsEnabled())
    GTEST_SKIP() << "host test: set KEYWARD_HOST_TESTS=1 to run against the real vault";

  // Throwaway app namespace so we never collide with a real app's credentials.
  // On Windows, defaultSecretStore("...") returns a WindowsCredentialStore.
  keyward::Vault vault{"keyward-host-smoke"};
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

  vault.remove(service);  // cleanup — leave the vault as we found it
  EXPECT_FALSE(vault.has(service));
}

#else  // not Windows

TEST(WindowsVaultSmoke, SkippedOffWindows) { GTEST_SKIP() << "Windows-only host smoke test"; }

#endif
