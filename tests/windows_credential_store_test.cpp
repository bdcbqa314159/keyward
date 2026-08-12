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

#else  // not Windows

TEST(WindowsCredentialStore, SkippedOffWindows) { GTEST_SKIP() << "Windows-only backend"; }

#endif
