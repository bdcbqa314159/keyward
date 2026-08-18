// Linux presence checks via polkit.
//
// BE CLEAR ABOUT WHAT THIS COVERS. The *granted* path needs a registered polkit
// authentication agent to answer the challenge, which a CI runner does not have
// and a test must not fake. So what is pinned here is the part that decides
// whether a user gets locked out: the Allowed / Denied / Unavailable mapping,
// and specifically that everything meaning "we could not ask" reports
// Unavailable — because FallbackAuthenticator degrades on Unavailable alone, and
// mapping a missing policy or a missing agent to Denied would strand a caller
// with no way forward.
#include "keyward/polkit_authenticator.hpp"

#include <gtest/gtest.h>

#include <memory>

#include "keyward/authenticator.hpp"
#include "keyward/fallback_authenticator.hpp"

#if defined(__linux__) && defined(KEYWARD_HAVE_POLKIT)

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

// The environment decides the answer, but never these two: a well-formed check
// must not throw, and it must not invent an Allowed it was never given.
TEST(PolkitAuthenticator, NeverThrowsAndNeverInventsAccess) {
  PolkitAuthenticator auth(/*allow_interaction=*/false);
  Authorization a = Authorization::Denied;
  ASSERT_NO_THROW(a = auth.authorize("jira", "read a secret"));

  // Without a registered agent (CI, or any headless session) the only honest
  // answers are "cannot ask" or a refusal. Allowed would mean polkit granted it
  // outright, which the shipped policy's allow_active=auth_self_keep does not do.
  EXPECT_TRUE(a == Authorization::Unavailable || a == Authorization::Denied ||
              a == Authorization::Cancelled)
      << "unexpected authorization value: " << static_cast<int>(a);
}

// Unavailable must be reported whenever no question could be asked. Note the
// converse does NOT hold, and asserting it would be wrong: with the shipped
// policy's allow_active=auth_self_keep, a check that forbids interaction gets
// `is_challenge` back — "authentication is required and possible" — which is
// still Unavailable, because nothing here can answer it. So availability implies
// a question *exists*, not that a non-interactive check resolves it.
TEST(PolkitAuthenticator, UnavailableWheneverNoQuestionCanBeAsked) {
  const bool available = polkit_available();
  PolkitAuthenticator auth(/*allow_interaction=*/false);
  const Authorization a = auth.authorize("jira", "read a secret");

  if (!available) {
    EXPECT_EQ(a, Authorization::Unavailable)
        << "no authority or no registered action, yet authorize() did not degrade";
  }
  SUCCEED() << "polkit_available()=" << available << " authorize()=" << static_cast<int>(a);
}

// The load-bearing integration, and the behaviour that would silently lock users
// out if "cannot ask" were mapped to Denied.
//
// Keyed off what polkit ACTUALLY answered rather than off availability, so it
// pins the FallbackAuthenticator contract in every environment: with no policy
// installed (CI, and this machine today), with the policy installed but no agent
// to answer the challenge, and on a desktop that resolves it.
TEST(PolkitAuthenticator, FallbackRunsExactlyWhenPolkitCouldNotAnswer) {
  PolkitAuthenticator probe(/*allow_interaction=*/false);
  const Authorization direct = probe.authorize("jira", "read a secret");

  auto spy = std::make_unique<SpyAuthenticator>();
  SpyAuthenticator* observer = spy.get();
  FallbackAuthenticator chain(std::make_unique<PolkitAuthenticator>(/*allow_interaction=*/false),
                              std::move(spy));
  const Authorization chained = chain.authorize("jira", "read a secret");

  if (direct == Authorization::Unavailable) {
    EXPECT_EQ(observer->calls, 1) << "polkit could not answer, but the fallback never ran";
    EXPECT_EQ(chained, Authorization::Allowed) << "the fallback's answer should stand";
  } else {
    // polkit answered for itself — a Denied here must NOT be overridden by a
    // more permissive tier.
    EXPECT_EQ(observer->calls, 0) << "polkit answered, yet the fallback was consulted anyway";
    EXPECT_EQ(chained, direct) << "polkit's own answer was not preserved";
  }
}

#else  // no polkit

TEST(PolkitAuthenticator, SkippedWithoutPolkit) {
  GTEST_SKIP() << "Linux polkit authenticator not built (needs pkg-config polkit-gobject-1)";
}

#endif
