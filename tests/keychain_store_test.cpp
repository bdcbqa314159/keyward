// macOS Keychain backend. The round-trip exercises the real login keychain, so
// it is opt-in (KEYWARD_HOST_TESTS=1) like the Windows/Linux smokes. The
// invalid-UTF-8 guard (M7) throws before any Keychain call, so it always runs.
#include <gtest/gtest.h>

#if defined(__APPLE__)

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>

#include "keyward/keychain_secret_store.hpp"

namespace {
bool hostTestsEnabled() {
  const char* v = std::getenv("KEYWARD_HOST_TESTS");
  return v != nullptr && std::string(v) == "1";
}
constexpr const char* kService = "keyward-keychain-test";
}  // namespace

// M7: a name that isn't valid UTF-8 must throw, not crash the process on
// CFRetain(NULL). No real keychain needed — the guard fires in baseQuery.
TEST(KeychainStore, RejectsInvalidUtf8Name) {
  keyward::KeychainSecretStore store{kService};
  const std::string bad("\x80", 1);  // lone continuation byte — invalid UTF-8
  EXPECT_THROW((void)store.get(bad), std::runtime_error);
  EXPECT_THROW(store.set(bad, "x"), std::runtime_error);
  EXPECT_THROW(store.remove(bad), std::runtime_error);
}

TEST(KeychainStore, RoundTripAgainstRealKeychain) {
  if (!hostTestsEnabled())
    GTEST_SKIP() << "host test: set KEYWARD_HOST_TESTS=1 to run against the real Keychain";
  keyward::KeychainSecretStore store{kService};
  store.remove("token");  // clean slate (ok if absent)

  EXPECT_FALSE(store.get("token").has_value());  // genuine miss -> nullopt, not throw
  store.set("token", "s3cr3t");
  EXPECT_EQ(store.get("token"), "s3cr3t");
  store.set("token", "rotated");  // upsert (update path, no delete-first)
  EXPECT_EQ(store.get("token"), "rotated");
  store.remove("token");  // verified delete
  EXPECT_FALSE(store.get("token").has_value());
  EXPECT_NO_THROW(store.remove("token"));  // removing an absent item is fine
}

#else

TEST(KeychainStore, SkippedOffApple) { GTEST_SKIP() << "macOS Keychain backend is Apple-only"; }

#endif  // __APPLE__
