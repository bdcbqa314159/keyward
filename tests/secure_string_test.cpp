// SecureString / SecureAllocator — the buffers a growing string leaves behind.
//
// `Secret` protects a buffer you still hold. Nothing protected the ones a
// growing std::string sheds: each reallocation copies the contents into a bigger
// block and frees the old one untouched, so `encode_fields` scattered prefixes
// of a serialized record — secret values included — across freed heap, where a
// closing `secure_zero(s.data(), s.size())` can never reach them.
#include "keyward/secure_string.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

#include "keyward/record.hpp"

using keyward::SecureAllocator;
using keyward::SecureString;

// The guarantee is structural: it holds because the container's allocator is
// ours, not because any particular call site remembered to wipe.
static_assert(std::is_same_v<SecureString::allocator_type, SecureAllocator<char>>,
              "SecureString must carry the zeroing allocator");

TEST(SecureString, ReleasedBlockNoLongerHoldsPlaintext) {
  SecureAllocator<char> alloc;
  constexpr std::size_t n = 4096;  // well past any SSO buffer
  constexpr char kPlaintext = 'S';

  char* first = alloc.allocate(n);
  std::memset(first, kPlaintext, n);
  alloc.deallocate(first, n);

  // Reading `first` now would be use-after-free. Instead ask for the same size
  // straight back: a same-size request in a tight sequence normally returns the
  // block just released, which we may legally read because it is ours again.
  char* again = alloc.allocate(n);
  if (again != first) {
    alloc.deallocate(again, n);
    GTEST_SKIP() << "allocator did not hand back the same block (ASan quarantine?) — "
                    "the release cannot be observed from here";
  }
  // Assert the SECRET is gone, not that the bytes are zero. MSVC's debug CRT
  // fills freed and fresh blocks with its own patterns (0xDD / 0xCD) after our
  // deallocate has run, so "all zeroes" is an implementation detail of one
  // platform; "none of our plaintext survives" is the property that matters and
  // holds on all of them.
  EXPECT_EQ(std::count(again, again + n, kPlaintext), 0) << "a released block still held plaintext";
  alloc.deallocate(again, n);
}

// The case that actually bit: growth. Every intermediate buffer is released
// through the allocator, so each is zeroed as it is shed.
TEST(SecureString, SurvivesRepeatedReallocation) {
  SecureString s;
  for (int i = 0; i < 2000; ++i) s += "secret";
  EXPECT_EQ(s.size(), 2000u * 6u);
  EXPECT_EQ(s.substr(0, 6), SecureString("secret"));
  EXPECT_TRUE(s.capacity() >= s.size());
}

TEST(SecureString, HoldsArbitraryBytesIncludingNuls) {
  const char raw[] = {'a', '\0', 'b', '\0', 'c'};
  SecureString s(raw, sizeof(raw));
  EXPECT_EQ(s.size(), 5u);
  EXPECT_EQ(s[1], '\0');
  // Converts to string_view without copying — this is how it reaches SecretStore.
  std::string_view v = s;
  EXPECT_EQ(v.size(), 5u);
  EXPECT_EQ(std::memcmp(v.data(), raw, sizeof(raw)), 0);
}

// The reason the type exists: the record encoder builds into one of these, so a
// serialized record never leaves prefixes behind while it grows.
TEST(SecureString, EncodeFieldsReturnsASecureString) {
  static_assert(std::is_same_v<decltype(keyward::encode_fields(keyward::Fields{})), SecureString>,
                "encode_fields must build into secure storage");
  const keyward::Fields fields{{"token", "s3cr3t"}, {"url", "https://example.com"}};
  SecureString blob = keyward::encode_fields(fields);
  ASSERT_FALSE(blob.empty());

  // Still round-trips through the decoder — hardening must not change the format.
  auto back = keyward::decode_fields(blob);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(*back, fields);
}
