// PassphraseKeyProvider — turns a gathered passphrase + the file's salt into the
// encryption key. Driven by a scripted PassphraseSource, so no tty is needed.
#include "keyward/key_provider.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <string_view>

#include "keyward/crypto_primitives.hpp"  // derive_key, kSaltSize
#include "keyward/random.hpp"

using keyward::derive_key;
using keyward::kSaltSize;
using keyward::PassphraseKeyProvider;
using keyward::random_bytes;

namespace {
keyward::PassphraseSource fixed(std::optional<std::string> value) {
  return [value = std::move(value)](std::string_view) { return value; };
}
}  // namespace

TEST(PassphraseKeyProvider, DerivesKeyMatchingDeriveKey) {
  std::string salt = random_bytes(kSaltSize);
  PassphraseKeyProvider provider{fixed("correct horse")};
  auto key = provider.unlock(salt, "unlock the store");
  ASSERT_TRUE(key.has_value());
  // Same passphrase + salt must yield exactly what derive_key would.
  EXPECT_EQ(key->view(), derive_key("correct horse", salt).view());
}

TEST(PassphraseKeyProvider, CancelReturnsNullopt) {
  PassphraseKeyProvider provider{fixed(std::nullopt)};
  EXPECT_FALSE(provider.unlock(random_bytes(kSaltSize), "unlock").has_value());
}

TEST(PassphraseKeyProvider, DifferentSaltDifferentKey) {
  PassphraseKeyProvider provider{fixed("pw")};
  auto k1 = provider.unlock(random_bytes(kSaltSize), "unlock");
  auto k2 = provider.unlock(random_bytes(kSaltSize), "unlock");
  ASSERT_TRUE(k1 && k2);
  EXPECT_NE(k1->view(), k2->view());
}

TEST(PassphraseKeyProvider, WrongPassphraseYieldsDifferentKey) {
  std::string salt = random_bytes(kSaltSize);
  auto right = PassphraseKeyProvider{fixed("pw")}.unlock(salt, "unlock");
  auto wrong = PassphraseKeyProvider{fixed("nope")}.unlock(salt, "unlock");
  ASSERT_TRUE(right && wrong);
  EXPECT_NE(right->view(), wrong->view());  // no verifier here — wrongness surfaces downstream
}
