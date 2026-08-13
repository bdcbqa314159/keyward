// Contract oracle for the Windows Credential Manager backend. Runs the REAL
// backend on Windows (uses a throwaway app namespace, cleans up after itself);
// compiles to a single GTEST_SKIP everywhere else so the suite stays green.
#include <gtest/gtest.h>

#if defined(_WIN32)

#include <string>

#include "keyward/windows_credential_store.hpp"

using namespace keyward;

namespace {
// Unique-ish namespace so the test never touches a real app's credentials.
WindowsCredentialStore freshStore() { return WindowsCredentialStore("keyward-test-cred"); }

// Removes a name on scope exit so a mid-test assertion failure never leaves a
// stray credential behind in the tester's Credential Manager. remove() only
// throws on unexpected OS errors (a missing name is a no-op) — swallow anything
// here since we must not throw from a destructor.
struct RemoveOnExit {
  WindowsCredentialStore* store;
  std::string name;
  ~RemoveOnExit() {
    try {
      store->remove(name);
    } catch (...) {
    }
  }
};
}  // namespace

TEST(WindowsCredentialStore, RoundTrips) {
  auto s = freshStore();
  s.remove("token");  // clean slate
  EXPECT_FALSE(s.get("token").has_value());

  s.set("token", "abc123");
  ASSERT_TRUE(s.get("token").has_value());
  EXPECT_EQ(s.get("token").value(), "abc123");

  s.set("token", "xyz789");  // upsert, not duplicate
  EXPECT_EQ(s.get("token").value(), "xyz789");

  s.remove("token");
  EXPECT_FALSE(s.get("token").has_value());
}

TEST(WindowsCredentialStore, PreservesEmbeddedNuls) {
  auto s = freshStore();
  const std::string raw("a\0b\0c", 5);  // arbitrary bytes, not a C string
  s.set("blob", raw);
  ASSERT_TRUE(s.get("blob").has_value());
  EXPECT_EQ(s.get("blob").value(), raw);
  EXPECT_EQ(s.get("blob").value().size(), 5u);
  s.remove("blob");
}

TEST(WindowsCredentialStore, FailsClosedOnOversizeBlob) {
  auto s = freshStore();
  const std::string tooBig(2561, 'x');  // > CRED_MAX_CREDENTIAL_BLOB_SIZE (2560)
  EXPECT_ANY_THROW(s.set("big", tooBig));
  EXPECT_FALSE(s.get("big").has_value());  // nothing stored
}

TEST(WindowsCredentialStore, BlobAtExactLimitSucceeds) {
  auto s = freshStore();
  RemoveOnExit cleanup{&s, "atlimit"};
  const std::string atLimit(2560, 'x');  // == CRED_MAX_CREDENTIAL_BLOB_SIZE
  ASSERT_NO_THROW(s.set("atlimit", atLimit));
  ASSERT_TRUE(s.get("atlimit").has_value());
  EXPECT_EQ(s.get("atlimit").value(), atLimit);
}

TEST(WindowsCredentialStore, EmptyValueRoundTrips) {
  auto s = freshStore();
  RemoveOnExit cleanup{&s, "empty"};
  s.set("empty", "");
  ASSERT_TRUE(s.get("empty").has_value());  // present, distinct from a miss
  EXPECT_EQ(s.get("empty").value(), "");
  EXPECT_EQ(s.get("empty").value().size(), 0u);
}

TEST(WindowsCredentialStore, UnicodeNameRoundTrips) {
  auto s = freshStore();
  const std::string name = "caf\xC3\xA9-token";  // "café-token" in UTF-8 — exercises toWide
  RemoveOnExit cleanup{&s, name};
  s.set(name, "secret");
  ASSERT_TRUE(s.get(name).has_value());
  EXPECT_EQ(s.get(name).value(), "secret");
}

#else  // not Windows

TEST(WindowsCredentialStore, SkippedOffWindows) { GTEST_SKIP() << "Windows-only backend"; }

#endif
