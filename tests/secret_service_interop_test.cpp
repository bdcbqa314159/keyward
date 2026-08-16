// Interop oracle for DESIGN.md's compatibility north star: "a secret written by
// Python `keyring` is readable by keyward and vice versa". This is the Linux
// half — keyring's SecretService backend and keyward's SecretServiceStore both
// talk to the same freedesktop Secret Service, so the test drives the REAL
// keyring CLI as the other side of the round trip.
//
// keyring is pinned in requirements-dev.txt and found by CMake at
// ${CMAKE_SOURCE_DIR}/.venv/bin/keyring; without it KEYWARD_KEYRING_CLI is
// undefined and this compiles to a single skip.
#include <gtest/gtest.h>

#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET) && defined(KEYWARD_KEYRING_CLI)

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "keyward/secret_service_store.hpp"

using keyward::SecretServiceStore;

namespace {

// Both sides must agree on this: it is keyring's `service` and keyward's `app`.
constexpr const char* kService = "keyward-interop-test";

bool secretServiceReachable() { return std::getenv("DBUS_SESSION_BUS_ADDRESS") != nullptr; }

// Shell-quote for single-quoted context. Test-only inputs, but a stray quote
// would corrupt the command rather than fail it, which is worse than a throw.
std::string shellQuote(const std::string& s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'')
      out += "'\\''";
    else
      out += c;
  }
  return out + "'";
}

// Runs the keyring CLI, returns {exitStatus, stdout}. stderr is folded in so a
// backend error shows up in the gtest failure rather than the terminal.
// `stdinData`, when non-empty, is piped in — `keyring set` takes the password
// that way. Piped from printf rather than a `<<<` herestring because popen runs
// /bin/sh, which is dash on Debian/Ubuntu and has no herestrings.
std::pair<int, std::string> keyringCli(const std::string& args, const std::string& stdinData = "");

std::pair<int, std::string> keyringCli(const std::string& args, const std::string& stdinData) {
  std::string cmd;
  if (!stdinData.empty()) cmd = "printf '%s' " + shellQuote(stdinData) + " | ";
  cmd += std::string(KEYWARD_KEYRING_CLI) + " " + args + " 2>&1";
  // Stateless deleter rather than decltype(&pclose): pclose carries attributes
  // that a function-pointer template argument would drag in (-Wignored-attributes).
  struct PcloseDeleter {
    void operator()(FILE* f) const { pclose(f); }
  };
  std::unique_ptr<FILE, PcloseDeleter> pipe(popen(cmd.c_str(), "r"));
  if (!pipe) return {-1, "popen failed"};
  std::string out;
  std::array<char, 256> buf{};
  while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get()) != nullptr) out += buf.data();
  const int status = pclose(pipe.release());
  if (!out.empty() && out.back() == '\n') out.pop_back();  // CLI adds a trailing newline
  return {status, out};
}

void keyringSet(const std::string& user, const std::string& password) {
  const auto [st, out] =
      keyringCli("set " + shellQuote(kService) + " " + shellQuote(user), password);
  ASSERT_EQ(st, 0) << "keyring set failed: " << out;
}

std::pair<int, std::string> keyringGet(const std::string& user) {
  return keyringCli("get " + shellQuote(kService) + " " + shellQuote(user));
}

void keyringDel(const std::string& user) {
  keyringCli("del " + shellQuote(kService) + " " + shellQuote(user));  // best effort
}

// Removes from BOTH sides on scope exit, so a mid-test failure leaves no
// residue in the developer's real keyring.
struct CleanUp {
  std::string user;
  ~CleanUp() {
    keyringDel(user);
    try {
      SecretServiceStore(kService).remove(user);
    } catch (...) {
    }
  }
};

#define SKIP_IF_NO_SERVICE() \
  if (!secretServiceReachable()) GTEST_SKIP() << "no DBUS_SESSION_BUS_ADDRESS"

}  // namespace

// The north star, direction 1: keyring writes, keyward reads.
TEST(SecretServiceInterop, KeywardReadsWhatPythonKeyringWrote) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"py-writes"};
  keyringSet("py-writes", "written-by-python");

  SecretServiceStore store(kService);
  auto got = store.get("py-writes");
  ASSERT_TRUE(got.has_value()) << "keyward could not see a keyring-written secret";
  EXPECT_EQ(*got, "written-by-python");
}

// The north star, direction 2: keyward writes, keyring reads.
TEST(SecretServiceInterop, PythonKeyringReadsWhatKeywardWrote) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"kw-writes"};
  SecretServiceStore store(kService);
  store.set("kw-writes", "written-by-keyward");

  const auto [st, out] = keyringGet("kw-writes");
  ASSERT_EQ(st, 0) << "keyring get failed: " << out;
  EXPECT_EQ(out, "written-by-keyward");
}

// Cross-tool overwrite: keyward replacing a keyring-written item must leave ONE
// item holding the new value, not two items with the old one still findable.
// This is what pins the "store exactly two attributes" decision — a third
// attribute of our own would make this write miss and create a duplicate.
TEST(SecretServiceInterop, KeywardOverwritesAKeyringWrittenItem) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"overwrite"};
  keyringSet("overwrite", "first-from-python");

  SecretServiceStore store(kService);
  store.set("overwrite", "second-from-keyward");

  EXPECT_EQ(store.get("overwrite").value_or("<missing>"), "second-from-keyward");
  const auto [st, out] = keyringGet("overwrite");
  ASSERT_EQ(st, 0) << "keyring get failed: " << out;
  EXPECT_EQ(out, "second-from-keyward") << "keyring still sees the pre-overwrite value";
}

// The reverse direction is NOT symmetric, and this is the interesting case.
// keyring stores a third attribute (application) that we don't, and Secret
// Service only replaces on an exact attribute-set match — so keyring writing
// over our item leaves TWO items: theirs (new) and ours (stale). keyward reads
// the most recently modified, so the caller still sees the current value.
//
// The sleep is load-bearing, not flake-padding: `modified` has one-second
// granularity, so without it both items share a timestamp and the situation is
// genuinely undecidable (asserted separately below).
TEST(SecretServiceInterop, KeyringOverwriteIsVisibleToKeywardOnceTimestampsDiffer) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"overwrite-rev"};
  SecretServiceStore store(kService);
  store.set("overwrite-rev", "first-from-keyward");

  std::this_thread::sleep_for(std::chrono::milliseconds(1100));  // cross a second boundary
  keyringSet("overwrite-rev", "second-from-python");

  EXPECT_EQ(store.get("overwrite-rev").value_or("<missing>"), "second-from-python");

  // And keyward's next write collapses the stale twin: one item, ours.
  store.set("overwrite-rev", "third-from-keyward");
  EXPECT_EQ(store.get("overwrite-rev").value_or("<missing>"), "third-from-keyward");
  const auto [st, out] = keyringGet("overwrite-rev");
  ASSERT_EQ(st, 0) << "keyring get failed: " << out;
  EXPECT_EQ(out, "third-from-keyward");
}

// The security invariant behind the duplicate handling: keyward NEVER silently
// hands back the stale twin. With back-to-back writes the two items may or may
// not share a `modified` second — that depends on machine speed, so asserting
// which happens would be a timing test. Either outcome is acceptable; returning
// the superseded value is not.
//
// (Both branches are reachable: on a normal build the writes usually tie and
// this throws; under ASan they usually don't and it returns "theirs".)
TEST(SecretServiceInterop, NeverReturnsTheStaleValueAfterAConflictingWrite) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"conflict"};
  SecretServiceStore store(kService);
  store.set("conflict", "ours");
  keyringSet("conflict", "theirs");  // no sleep: may or may not share a second

  try {
    auto got = store.get("conflict");
    // Resolved by timestamp — it must be the newer write.
    EXPECT_EQ(got.value_or("<missing>"), "theirs") << "returned a superseded secret";
  } catch (const std::runtime_error&) {
    SUCCEED() << "undecidable (same second) — refused rather than guessing";
  }

  store.set("conflict", "resolved");  // a write collapses the duplicates
  EXPECT_EQ(store.get("conflict").value_or("<missing>"), "resolved");
}

// A delete on one side must be visible as a miss on the other.
TEST(SecretServiceInterop, KeywardRemoveIsVisibleToKeyring) {
  SKIP_IF_NO_SERVICE();
  CleanUp cleanup{"removed"};
  keyringSet("removed", "doomed");

  SecretServiceStore store(kService);
  store.remove("removed");

  EXPECT_FALSE(store.get("removed").has_value());
  const auto [st, out] = keyringGet("removed");
  EXPECT_NE(st, 0) << "keyring still finds a secret keyward removed: " << out;
}

// list() must surface names written by the other client, not just our own.
TEST(SecretServiceInterop, ListSeesKeyringWrittenNames) {
  SKIP_IF_NO_SERVICE();
  CleanUp ca{"listed-py"};
  CleanUp cb{"listed-kw"};
  keyringSet("listed-py", "1");
  SecretServiceStore store(kService);
  store.set("listed-kw", "2");

  const auto names = store.list();
  const auto has = [&](const std::string& n) {
    return std::find(names.begin(), names.end(), n) != names.end();
  };
  EXPECT_TRUE(has("listed-py")) << "keyring-written name missing from list()";
  EXPECT_TRUE(has("listed-kw"));
}

#else  // no libsecret, or keyring CLI not found at configure time

TEST(SecretServiceInterop, SkippedWithoutLibsecretOrKeyring) {
  GTEST_SKIP() << "needs Linux + libsecret + the pinned `keyring` "
                  "(python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt)";
}

#endif
