// PassphraseAuthenticator + the verifier utility. A scripted source stands in
// for terminal input, so nothing here needs a tty.
#include "keyward/passphrase_authenticator.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using keyward::Authorization;
using keyward::make_passphrase_verifier;
using keyward::PassphraseAuthenticator;
using keyward::verify_passphrase;

namespace {

// Returns the canned responses in order; std::nullopt means "cancel". The mutable
// lambda's index persists across calls on the same std::function instance.
keyward::PassphraseSource scripted(std::vector<std::optional<std::string>> responses) {
  return [responses = std::move(responses),
          i = std::size_t{0}](std::string_view) mutable -> std::optional<std::string> {
    if (i >= responses.size()) return std::nullopt;
    return responses[i++];
  };
}

}  // namespace

TEST(PassphraseVerifier, RoundTrips) {
  auto v = make_passphrase_verifier("correct horse");
  EXPECT_TRUE(verify_passphrase("correct horse", v));
  EXPECT_FALSE(verify_passphrase("wrong", v));
}

TEST(PassphraseVerifier, FreshSaltEachTime) {
  // same passphrase -> different verifier blobs (random salt)
  EXPECT_NE(make_passphrase_verifier("pw"), make_passphrase_verifier("pw"));
}

TEST(PassphraseVerifier, RejectsMalformedVerifier) {
  EXPECT_FALSE(verify_passphrase("x", ""));
  EXPECT_FALSE(verify_passphrase("x", "too short"));
}

// L3: enrolling an empty passphrase would mint a verifier that unlocks on "".
TEST(PassphraseVerifier, RejectsEmptyEnrollment) {
  EXPECT_THROW(make_passphrase_verifier(""), std::invalid_argument);
}

// M3: the blob is version ‖ 16-byte salt ‖ 32-byte hash, and a verifier tagged
// with a cost profile we don't know must fail closed (we can't reproduce it).
TEST(PassphraseVerifier, CarriesCostProfileVersion) {
  auto v = make_passphrase_verifier("pw");
  ASSERT_EQ(v.size(), 1u + 16u + 32u);
  EXPECT_EQ(static_cast<unsigned char>(v[0]), 1u);  // current profile id

  std::string unknown = v;
  unknown[0] = static_cast<char>(0xFE);  // retag to a profile that doesn't exist
  EXPECT_FALSE(verify_passphrase("pw", unknown));
}

TEST(PassphraseAuth, CorrectAllows) {
  PassphraseAuthenticator auth{make_passphrase_verifier("pw"), scripted({"pw"})};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Allowed);
}

TEST(PassphraseAuth, WrongDeniedAfterAttempts) {
  PassphraseAuthenticator auth{make_passphrase_verifier("pw"), scripted({"a", "b", "c"}), 3};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Denied);
}

TEST(PassphraseAuth, RetryThenSucceed) {
  PassphraseAuthenticator auth{make_passphrase_verifier("pw"), scripted({"nope", "pw"}), 3};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Allowed);
}

TEST(PassphraseAuth, CancelReturnsCancelled) {
  PassphraseAuthenticator auth{make_passphrase_verifier("pw"), scripted({std::nullopt})};
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Cancelled);
}
