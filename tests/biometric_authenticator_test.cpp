// Windows Hello presence checks via UserConsentVerifier.
//
// BE CLEAR ABOUT WHAT THIS COVERS — and why it deliberately does NOT drive the
// granted path. authorize() raises an interactive Hello prompt (face / fingerprint
// / PIN) hosted by CredentialUIBroker. On a machine WITH Hello configured, calling
// it pops a real dialog and BLOCKS until a human answers — so an automated test
// must never call authorize() when Hello is available, exactly as the macOS Touch
// ID smoke in fallback_authenticator_test.cpp never drives LAContext. The granted
// path is a manual smoke (see docs/AUTHENTICATOR.md), not a CI test.
//
// What IS pinned here is the part that decides whether a user gets locked out:
// biometric_available() is queryable and never throws; and when Hello is
// unavailable (CI runners, no biometric hardware / no enrolled user) authorize()
// degrades to Unavailable WITHOUT prompting — because RequestVerificationForWindow
// returns DeviceNotPresent/NotConfiguredForUser with no UI in that case — so a
// FallbackAuthenticator reaches the passphrase tier instead of stranding the user.
// Mapping "no Hello" to Denied would be the silent lock-out this guards against.
#include "keyward/biometric_authenticator.hpp"

#include <gtest/gtest.h>

#include <memory>

#include "keyward/authenticator.hpp"
#include "keyward/fallback_authenticator.hpp"

#if defined(_WIN32)

using namespace keyward;

namespace {

// Stands in for the passphrase tier: records whether the fallback was reached.
class SpyAuthenticator : public Authenticator {
 public:
  Authorization authorize(std::string_view, std::string_view) override {
    ++calls;
    return Authorization::Allowed;
  }
  int calls = 0;
};

}  // namespace

// The type links on every Windows build and availability is queryable without
// throwing. This is the always-safe smoke (no prompt can appear) — the analogue of
// the macOS Biometric.LinksAndReportsAvailability test.
TEST(BiometricAuthenticator, LinksAndAvailabilityIsQueryable) {
  BiometricAuthenticator auth{"Use passphrase"};
  bool avail = true;
  ASSERT_NO_THROW(avail = biometric_available());
  (void)auth;
  SUCCEED() << "biometric_available()=" << avail;
}

// The load-bearing contract, tested ONLY where it is safe to call authorize():
// when Hello is unavailable, no dialog is shown, so we can assert that (a) it
// degrades to Unavailable and never throws or invents access, and (b) a
// FallbackAuthenticator consequently runs the next tier. On a box WITH Hello this
// skips — the granted path is interactive and is verified by hand, not here.
TEST(BiometricAuthenticator, UnavailableDegradesToFallbackWithoutPrompting) {
  if (biometric_available()) {
    GTEST_SKIP() << "Hello is available on this box; authorize() would prompt a human — "
                    "the granted path is a manual smoke (see docs/AUTHENTICATOR.md)";
  }

  BiometricAuthenticator bio{""};
  Authorization direct = Authorization::Allowed;
  ASSERT_NO_THROW(direct = bio.authorize("jira", "read a secret"));
  EXPECT_EQ(direct, Authorization::Unavailable)
      << "no Hello available, yet authorize() did not degrade to Unavailable (value "
      << static_cast<int>(direct) << ")";

  auto spy = std::make_unique<SpyAuthenticator>();
  SpyAuthenticator* observer = spy.get();
  FallbackAuthenticator chain(std::make_unique<BiometricAuthenticator>(""), std::move(spy));
  EXPECT_EQ(chain.authorize("jira", "read a secret"), Authorization::Allowed)
      << "Hello could not answer, but the fallback's answer did not stand";
  EXPECT_EQ(observer->calls, 1) << "Hello could not answer, but the fallback never ran";
}

#else  // no Windows Hello

TEST(BiometricAuthenticator, SkippedWithoutWindowsHello) {
  GTEST_SKIP() << "Windows Hello authenticator not built (needs _WIN32 / UserConsentVerifier)";
}

#endif
