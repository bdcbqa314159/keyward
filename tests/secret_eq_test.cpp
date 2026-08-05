// Oracle for Task 2 — Secret::equals (constant-time compare). Make it green by
// adding `bool Secret::equals(std::string_view) const noexcept;`. The timing
// property is verified by review, not here. Don't edit this file to pass.
#include <gtest/gtest.h>

#include "keyward/secret.hpp"

using keyward::Secret;

TEST(SecretEquals, MatchesIdenticalBytes) {
  Secret s("hunter2");
  EXPECT_TRUE(s.equals("hunter2"));
}

TEST(SecretEquals, RejectsSameLengthDifference) {
  Secret s("hunter2");
  EXPECT_FALSE(s.equals("hunter3"));  // differs in the last byte
  EXPECT_FALSE(s.equals("Xunter2"));  // differs in the first byte
}

TEST(SecretEquals, RejectsDifferentLengths) {
  Secret s("hunter2");
  EXPECT_FALSE(s.equals("hunter"));    // shorter
  EXPECT_FALSE(s.equals("hunter22"));  // longer
  EXPECT_FALSE(s.equals(""));          // empty candidate
}

TEST(SecretEquals, EmptySecret) {
  Secret e("");
  EXPECT_TRUE(e.equals(""));
  EXPECT_FALSE(e.equals("x"));
}
