// Contract oracle for the Linux Secret Service backend. Runs the REAL backend
// against the user's keyring daemon (throwaway app namespace, cleans up after
// itself); compiles to a single GTEST_SKIP where libsecret isn't available, so
// the suite stays green cross-platform and on a Linux box without the dep.
#include <gtest/gtest.h>

#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

#include "keyward/secret_service_store.hpp"

using namespace keyward;

namespace {

// Secret Service is a D-Bus session service. No session bus => no keyring
// daemon => nothing to test against (headless server, ssh without a session,
// a container). Skip rather than fail: this is an environment fact, not a bug.
// If a bus IS present but no secrets provider answers, we deliberately let the
// test FAIL loudly instead of widening this probe — a silent skip there would
// hide a broken backend.
bool secretServiceReachable() { return std::getenv("DBUS_SESSION_BUS_ADDRESS") != nullptr; }

// Unique-ish namespace so the test never touches a real app's secrets.
SecretServiceStore freshStore() { return SecretServiceStore("keyward-test-secretservice"); }

// Removes a name on scope exit so a mid-test assertion failure never leaves a
// stray item behind in the tester's keyring. remove() only throws on unexpected
// errors (a missing name is a no-op) — swallow anything here since we must not
// throw from a destructor.
struct RemoveOnExit {
  SecretServiceStore* store;
  std::string name;
  ~RemoveOnExit() {
    try {
      store->remove(name);
    } catch (...) {
    }
  }
};

}  // namespace

#define SKIP_IF_NO_SERVICE()                         \
  if (!secretServiceReachable())                     \
  GTEST_SKIP() << "no DBUS_SESSION_BUS_ADDRESS — " \
                  "no Secret Service to test against"

TEST(SecretServiceStore, RoundTrips) {
  SKIP_IF_NO_SERVICE();
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

// THE load-bearing one. Vault::save stores encode_fields() output — length-
// prefixed binary that routinely contains NUL bytes. A backend that truncates
// at the first NUL corrupts every saved record while looking like it works.
TEST(SecretServiceStore, PreservesEmbeddedNuls) {
  SKIP_IF_NO_SERVICE();
  auto s = freshStore();
  RemoveOnExit cleanup{&s, "blob"};
  const std::string raw("a\0b\0c", 5);  // arbitrary bytes, not a C string
  s.set("blob", raw);
  ASSERT_TRUE(s.get("blob").has_value());
  EXPECT_EQ(s.get("blob").value(), raw);
  EXPECT_EQ(s.get("blob").value().size(), 5u);
}

TEST(SecretServiceStore, EmptyValueRoundTrips) {
  SKIP_IF_NO_SERVICE();
  auto s = freshStore();
  RemoveOnExit cleanup{&s, "empty"};
  s.set("empty", "");
  ASSERT_TRUE(s.get("empty").has_value());  // present, distinct from a miss
  EXPECT_EQ(s.get("empty").value(), "");
  EXPECT_EQ(s.get("empty").value().size(), 0u);
}

TEST(SecretServiceStore, UnicodeNameRoundTrips) {
  SKIP_IF_NO_SERVICE();
  auto s = freshStore();
  const std::string name = "caf\xC3\xA9-token";  // "café-token" in UTF-8
  RemoveOnExit cleanup{&s, name};
  s.set(name, "secret");
  ASSERT_TRUE(s.get(name).has_value());
  EXPECT_EQ(s.get(name).value(), "secret");
}

TEST(SecretServiceStore, RemoveIsSurgicalAndIdempotent) {
  SKIP_IF_NO_SERVICE();
  auto s = freshStore();
  RemoveOnExit ca{&s, "keep"};
  s.set("keep", "1");
  s.set("drop", "2");

  s.remove("drop");
  EXPECT_FALSE(s.get("drop").has_value());
  ASSERT_TRUE(s.get("keep").has_value());  // untouched
  EXPECT_EQ(s.get("keep").value(), "1");

  EXPECT_NO_THROW(s.remove("drop"));  // missing name is a no-op, not an error
  EXPECT_NO_THROW(s.remove("never-set"));
}

TEST(SecretServiceStore, ListReturnsStoredNamesWithinNamespace) {
  SKIP_IF_NO_SERVICE();
  auto s = freshStore();
  RemoveOnExit ca{&s, "list-a"};
  RemoveOnExit cb{&s, "list-b"};
  s.set("list-a", "1");
  s.set("list-b", "2");

  const std::vector<std::string> names = s.list();
  const auto has = [&](const std::string& n) {
    return std::find(names.begin(), names.end(), n) != names.end();
  };
  EXPECT_TRUE(has("list-a"));
  EXPECT_TRUE(has("list-b"));
  // Names come back unqualified (no namespace prefix leaking through).
  for (const auto& n : names) EXPECT_EQ(n.find("keyward:"), std::string::npos);
}

// A different app namespace must not see this one's secrets.
TEST(SecretServiceStore, NamespacesAreIsolated) {
  SKIP_IF_NO_SERVICE();
  auto mine = freshStore();
  SecretServiceStore theirs("keyward-test-secretservice-other");
  RemoveOnExit cleanup{&mine, "shared-name"};
  mine.set("shared-name", "mine");
  EXPECT_FALSE(theirs.get("shared-name").has_value());
}

#else  // no libsecret

TEST(SecretServiceStore, SkippedWithoutLibsecret) {
  GTEST_SKIP() << "Linux Secret Service backend not built (needs pkg-config libsecret-1)";
}

#endif
