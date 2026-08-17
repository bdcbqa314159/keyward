// FallbackAuthenticator + a compile/link smoke of BiometricAuthenticator. The
// biometric prompt itself is interactive (real Touch ID), so it isn't driven
// here — CI proves it compiles per-platform; the fallback POLICY is fully tested
// with fakes.
#include "keyward/fallback_authenticator.hpp"

#include <gtest/gtest.h>

#include <memory>

#include "keyward/authenticator.hpp"
#include "keyward/biometric_authenticator.hpp"

using keyward::Authorization;

namespace {

// An authenticator that always returns a fixed verdict, counting calls.
class Fixed : public keyward::Authenticator {
 public:
  explicit Fixed(Authorization r) : r_(r) {}
  int calls = 0;
  Authorization authorize(std::string_view, std::string_view) override {
    ++calls;
    return r_;
  }

 private:
  Authorization r_;
};

std::unique_ptr<Fixed> fixed(Authorization r) { return std::make_unique<Fixed>(r); }

}  // namespace

TEST(Fallback, UnavailablePrimaryFallsThrough) {
  auto prim = fixed(Authorization::Unavailable);
  auto fb = fixed(Authorization::Allowed);
  Fixed* fbp = fb.get();
  keyward::FallbackAuthenticator auth{std::move(prim), std::move(fb)};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Allowed);
  EXPECT_EQ(fbp->calls, 1);  // fallback was consulted
}

TEST(Fallback, AllowedPrimaryDoesNotFallThrough) {
  auto fb = fixed(Authorization::Denied);
  Fixed* fbp = fb.get();
  keyward::FallbackAuthenticator auth{fixed(Authorization::Allowed), std::move(fb)};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Allowed);
  EXPECT_EQ(fbp->calls, 0);  // never reached the fallback
}

TEST(Fallback, DeniedPrimaryIsRespectedNotDowngraded) {
  // A denied biometric must NOT silently downgrade to the passphrase path.
  auto fb = fixed(Authorization::Allowed);
  Fixed* fbp = fb.get();
  keyward::FallbackAuthenticator auth{fixed(Authorization::Denied), std::move(fb)};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Denied);
  EXPECT_EQ(fbp->calls, 0);
}

TEST(Fallback, CancelledPrimaryIsRespected) {
  keyward::FallbackAuthenticator auth{fixed(Authorization::Cancelled),
                                      fixed(Authorization::Allowed)};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Cancelled);
}

TEST(Biometric, LinksAndReportsAvailability) {
  // Smoke: the type links on every platform and availability is queryable.
  // (Off-macOS this is always false; on macOS it depends on hardware/enrolment.)
  keyward::BiometricAuthenticator bio{"Use passphrase"};
  bool avail = keyward::biometric_available();
  (void)bio;
  (void)avail;
  SUCCEED();
}
