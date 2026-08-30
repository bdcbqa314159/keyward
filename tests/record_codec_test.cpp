// Oracle for Task 4 — the record codec. Make it green by implementing
// encode_fields / decode_fields in src/record_codec.cpp. Don't edit this file
// to pass.
#include <gtest/gtest.h>

#include <string>
#include <type_traits>

#include "keyward/record.hpp"
#include "keyward/secure_string.hpp"

using keyward::decode_fields;
using keyward::encode_fields;
using keyward::Fields;

// R3-3: the Fields backing store must use the zeroing allocator, so short (SSO)
// field values shed by a push_back reallocation don't linger in freed heap. The
// actual leak only reproduces on stdlibs that don't zero moved-from SSO buffers
// (libstdc++), so guard the fix structurally here instead of via a flaky
// heap-inspection test: this fails deterministically if the alias is reverted.
static_assert(std::is_same_v<Fields::allocator_type, keyward::SecureAllocator<keyward::Field>>,
              "Fields must use SecureAllocator (R3-3): std::allocator leaks SSO values on realloc");

TEST(RecordCodec, RoundTripsMultipleFields) {
  Fields in{{"email", "a@b.com"}, {"url", "https://x"}, {"token", "abc123"}};
  auto out = decode_fields(encode_fields(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}

TEST(RecordCodec, PreservesOrder) {
  Fields in{{"z", "1"}, {"a", "2"}, {"m", "3"}};
  auto out = decode_fields(encode_fields(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);  // order intact, not sorted
}

TEST(RecordCodec, EmptyValueAndEmptyName) {
  Fields in{{"present", ""}, {"", "no-name"}};
  auto out = decode_fields(encode_fields(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}

TEST(RecordCodec, EmptyFieldList) {
  auto out = decode_fields(encode_fields({}));
  ASSERT_TRUE(out.has_value());
  EXPECT_TRUE(out->empty());
}

TEST(RecordCodec, BinarySafeValues) {
  // names and values may hold any byte — NUL, '=', newline
  Fields in{{"blob", std::string("a\0b=c\n", 6)}, {"k", "v"}};
  auto out = decode_fields(encode_fields(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}

TEST(RecordCodec, TruncatedBlobIsRejectedNotUB) {
  auto blob = encode_fields({{"email", "a@b.com"}, {"token", "abc"}});
  ASSERT_FALSE(blob.empty());
  blob.resize(blob.size() / 2);  // chop mid-record
  EXPECT_FALSE(decode_fields(blob).has_value());
}

TEST(RecordCodec, DroppedLastByteIsRejected) {
  // losing one byte makes the final field's declared length overrun the buffer;
  // the decoder must reject it, not read past the end. (Run under asan.)
  auto blob = encode_fields({{"email", "a@b.com"}, {"token", "abc"}});
  ASSERT_FALSE(blob.empty());
  blob.pop_back();
  EXPECT_FALSE(decode_fields(blob).has_value());
}

TEST(RecordCodec, BlobStartsWithVersionByte) {
  auto blob = encode_fields({{"k", "v"}});
  ASSERT_FALSE(blob.empty());
  EXPECT_EQ(static_cast<unsigned char>(blob[0]), 1u);  // current format version
}

TEST(RecordCodec, RejectsUnknownVersion) {
  auto blob = encode_fields({{"email", "a@b.com"}, {"token", "abc"}});
  blob[0] = static_cast<char>(0xFF);  // a version we don't understand
  EXPECT_FALSE(decode_fields(blob).has_value());
}

TEST(RecordCodec, RejectsEmptyBlob) {
  EXPECT_FALSE(decode_fields("").has_value());  // no version byte at all
}
