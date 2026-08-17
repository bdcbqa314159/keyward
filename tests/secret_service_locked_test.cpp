// Locked-keyring behaviour for the Secret Service backend.
//
// A locked collection still answers searches: the item's ATTRIBUTES come back,
// its secret does not. The backend used to treat that absent value as "no such
// secret" — which on Linux is a real downgrade, because defaultSecretStore puts
// a plaintext file store behind the keyring, so the miss fell through to the
// weaker tier while the actual secret sat locked and untouched.
//
// MUST run under tests/run_isolated_keyring.sh: locking the default collection
// is global, and doing it to a developer's live session would lock their login
// keyring out from under every other application. The test refuses to run
// without the marker that script sets.
#include <gtest/gtest.h>

#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)

#include <cstdlib>
#include <stdexcept>
#include <string>

#include "keyward/secret_service_store.hpp"

using keyward::SecretServiceStore;

namespace {

bool isolated() {
  const char* v = std::getenv("KEYWARD_ISOLATED_KEYRING");
  return v != nullptr && std::string(v) == "1";
}

// Locks via the spec's *alias* path rather than a provider-specific collection
// path, so this isn't gnome-keyring-only.
int lockDefaultCollection() {
  return std::system(
      "gdbus call --session --dest org.freedesktop.secrets "
      "--object-path /org/freedesktop/secrets "
      "--method org.freedesktop.Secret.Service.Lock "
      "\"['/org/freedesktop/secrets/aliases/default']\" >/dev/null 2>&1");
}

#define REQUIRE_ISOLATION()                                    \
  if (!isolated())                                             \
  GTEST_SKIP() << "run via tests/run_isolated_keyring.sh — " \
                  "this test locks the default collection"

}  // namespace

// Both observations live in ONE test on purpose. Locking is global and there is
// no way to unlock again without a prompter, so the first test to lock would
// leave every later one writing to a locked collection. One lock, both checks.
TEST(SecretServiceLocked, GetRefusesWhileListStillWorks) {
  REQUIRE_ISOLATION();
  SecretServiceStore store("keyward-lock-test");

  // Unlocked control, so a failure below can't be "it never stored anything".
  store.set("tok", "the-real-secret");
  ASSERT_EQ(store.get("tok").value_or("<missing>"), "the-real-secret");
  ASSERT_EQ(store.list().size(), 1u);

  ASSERT_EQ(lockDefaultCollection(), 0) << "could not lock the collection";

  // The secret is present but unreadable. Anything other than a throw is a
  // downgrade: nullopt would mean "no such secret" and, through
  // defaultSecretStore's fallback chain, drop to the plaintext file store.
  EXPECT_THROW(store.get("tok"), std::runtime_error);

  // list() reads attributes only, which stay readable while locked — which is
  // why it deliberately does NOT pass SECRET_SEARCH_UNLOCK. Prompting the user
  // merely to enumerate names would be a worse trade than answering.
  const auto names = store.list();
  ASSERT_EQ(names.size(), 1u) << "locked collection should still yield attributes";
  EXPECT_EQ(names[0], "tok");

  // remove() must not claim success. A locked collection makes clear() a no-op
  // that reports no error, so returning normally here would tell a caller
  // revoking a credential that it was deleted while it sits in the keyring.
  EXPECT_THROW(store.remove("tok"), std::runtime_error);
  EXPECT_EQ(store.list().size(), 1u) << "still there — which is exactly why remove() must throw";
}

#else  // no libsecret

TEST(SecretServiceLocked, SkippedWithoutLibsecret) {
  GTEST_SKIP() << "Linux Secret Service backend not built";
}

#endif
