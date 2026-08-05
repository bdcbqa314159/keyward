// Oracle for Task 3 — passphrase-based seal/unseal (Argon2 + XChaCha20-Poly1305,
// via the vendored Monocypher). Make it green by implementing seal() and
// unseal() in src/secret_box.cpp. Don't edit this file to pass.
#include "keyward/secret_box.hpp"

#include <gtest/gtest.h>

#include <string>

using keyward::seal;
using keyward::unseal;

TEST(SecretBox, RoundTrips) {
  auto blob = seal("hunter2", "correct horse battery staple");
  auto out = unseal(blob, "correct horse battery staple");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, "hunter2");
}

TEST(SecretBox, WrongPassphraseFails) {
  auto blob = seal("hunter2", "correct horse battery staple");
  EXPECT_FALSE(unseal(blob, "Tr0ub4dour&3").has_value());
}

TEST(SecretBox, TamperedBlobFails) {
  auto blob = seal("hunter2", "pw");
  ASSERT_FALSE(blob.empty());
  blob[blob.size() / 2] ^= 0x01;  // flip one bit somewhere in the middle
  EXPECT_FALSE(unseal(blob, "pw").has_value());
}

TEST(SecretBox, EmptyPlaintextRoundTrips) {
  auto blob = seal("", "pw");
  auto out = unseal(blob, "pw");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, "");
}

TEST(SecretBox, SaltAndNonceAreFresh) {
  // Same inputs, two seals -> different blobs (fresh random salt + nonce).
  EXPECT_NE(seal("hunter2", "pw"), seal("hunter2", "pw"));
}

TEST(SecretBox, TruncatedBlobIsRejectedNotUB) {
  // A short/garbage blob must return nullopt, never read out of bounds.
  // (Run under the asan preset — this catches a missing length check.)
  auto blob = seal("hunter2", "pw");
  blob.resize(blob.size() / 2);
  EXPECT_FALSE(unseal(blob, "pw").has_value());
  EXPECT_FALSE(unseal("", "pw").has_value());
}
