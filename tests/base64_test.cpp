// The shared base64 utility (used by the encrypted format and the plaintext
// file tier). Strict decode: fail-closed on garbage.
#include "keyward/base64.hpp"

#include <gtest/gtest.h>

#include <string>

using keyward::base64_decode;
using keyward::base64_encode;

TEST(Base64, RoundTripsArbitraryBytes) {
  for (const std::string& s :
       {std::string(""), std::string("a"), std::string("ab"), std::string("abc"),
        std::string("hello world"), std::string("\x00\x01\x02\xff\xfe", 5),
        std::string("line\nwith\nnewlines"), std::string("trailing space ")}) {
    auto dec = base64_decode(base64_encode(s));
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, s);
  }
}

TEST(Base64, KnownVectors) {
  EXPECT_EQ(base64_encode("f"), "Zg==");
  EXPECT_EQ(base64_encode("fo"), "Zm8=");
  EXPECT_EQ(base64_encode("foo"), "Zm9v");
  EXPECT_EQ(base64_decode("Zm9vYmFy").value_or("?"), "foobar");
}

TEST(Base64, RejectsGarbage) {
  EXPECT_FALSE(base64_decode("abc").has_value());   // length not %4
  EXPECT_FALSE(base64_decode("ab!c").has_value());  // non-alphabet
  EXPECT_FALSE(base64_decode("a==b").has_value());  // padding not at end
  EXPECT_FALSE(base64_decode("====").has_value());  // all padding
}
