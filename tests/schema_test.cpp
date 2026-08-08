// Oracle for Task 5 — typed schema mapping. Make it green by implementing
// to_fields / from_fields in include/keyward/schema.hpp. Don't edit this file.
#include "keyward/schema.hpp"

#include <gtest/gtest.h>

#include <string>

#include "keyward/record.hpp"

namespace {

// A stand-in credential type: three string fields + a schema listing them once.
struct DemoCred {
  std::string email;
  std::string url;
  std::string token;
  bool operator==(const DemoCred&) const = default;

  static keyward::Schema<DemoCred> schema() {
    return {
        {"email", &DemoCred::email},
        {"url", &DemoCred::url},
        {"token", &DemoCred::token, keyward::Sensitive},
    };
  }
};

}  // namespace

using keyward::Fields;
using keyward::from_fields;
using keyward::to_fields;

TEST(Schema, ToFieldsInSchemaOrder) {
  DemoCred c{"a@b.com", "https://x", "tok"};
  Fields expected{{"email", "a@b.com"}, {"url", "https://x"}, {"token", "tok"}};
  EXPECT_EQ(to_fields(c), expected);
}

TEST(Schema, RoundTripsThroughFields) {
  DemoCred c{"a@b.com", "https://x", "tok"};
  auto back = from_fields<DemoCred>(to_fields(c));
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(*back, c);
}

TEST(Schema, FromFieldsRebuildsMembers) {
  Fields in{{"email", "e"}, {"url", "u"}, {"token", "t"}};
  auto c = from_fields<DemoCred>(in);
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(c->email, "e");
  EXPECT_EQ(c->url, "u");
  EXPECT_EQ(c->token, "t");
}

TEST(Schema, MissingSchemaFieldIsNullopt) {
  Fields in{{"email", "e"}, {"url", "u"}};  // token absent
  EXPECT_FALSE(from_fields<DemoCred>(in).has_value());
}

TEST(Schema, OrderIndependentAndIgnoresExtra) {
  Fields in{{"token", "t"}, {"junk", "x"}, {"url", "u"}, {"email", "e"}};
  auto c = from_fields<DemoCred>(in);
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(*c, (DemoCred{"e", "u", "t"}));
}
