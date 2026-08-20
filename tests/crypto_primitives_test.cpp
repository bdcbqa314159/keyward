// The low-level KDF + AEAD primitives under seal/unseal. These are what the
// encrypted file store will use: derive a key once, then aead_seal/aead_open
// per entry with distinct nonces.
#include "keyward/crypto_primitives.hpp"

#include <gtest/gtest.h>

#include <string>

#include "keyward/random.hpp"
#include "keyward/secret.hpp"

using keyward::aead_open;
using keyward::aead_seal;
using keyward::derive_key;
using keyward::kNonceSize;
using keyward::kSaltSize;
using keyward::random_bytes;
using keyward::Secret;

TEST(DeriveKey, DeterministicForSamePassphraseAndSalt) {
  std::string salt = random_bytes(kSaltSize);
  Secret a = derive_key("correct horse", salt);
  Secret b = derive_key("correct horse", salt);
  EXPECT_EQ(a.view(), b.view());
  EXPECT_EQ(a.size(), 32u);
}

TEST(DeriveKey, DiffersByPassphraseAndBySalt) {
  std::string salt1 = random_bytes(kSaltSize);
  std::string salt2 = random_bytes(kSaltSize);
  EXPECT_NE(derive_key("pw", salt1).view(), derive_key("other", salt1).view());  // passphrase
  EXPECT_NE(derive_key("pw", salt1).view(), derive_key("pw", salt2).view());     // salt
}

TEST(Aead, RoundTrips) {
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string nonce = random_bytes(kNonceSize);
  std::string sealed = aead_seal(key, nonce, "hunter2");
  auto out = aead_open(key, nonce, sealed);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->view(), "hunter2");
}

TEST(Aead, EmptyPlaintextRoundTrips) {
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string nonce = random_bytes(kNonceSize);
  auto out = aead_open(key, nonce, aead_seal(key, nonce, ""));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->view(), "");
}

TEST(Aead, WrongKeyFails) {
  std::string salt = random_bytes(kSaltSize);
  std::string nonce = random_bytes(kNonceSize);
  std::string sealed = aead_seal(derive_key("pw", salt), nonce, "hunter2");
  EXPECT_FALSE(aead_open(derive_key("wrong", salt), nonce, sealed).has_value());
}

TEST(Aead, WrongNonceFails) {
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string sealed = aead_seal(key, random_bytes(kNonceSize), "hunter2");
  EXPECT_FALSE(aead_open(key, random_bytes(kNonceSize), sealed).has_value());
}

TEST(Aead, TamperedCiphertextFails) {
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string nonce = random_bytes(kNonceSize);
  std::string sealed = aead_seal(key, nonce, "hunter2");
  sealed[sealed.size() - 1] ^= 0x01;  // flip a ciphertext bit
  EXPECT_FALSE(aead_open(key, nonce, sealed).has_value());
}

TEST(Aead, TruncatedBelowMacRejected) {
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string nonce = random_bytes(kNonceSize);
  EXPECT_FALSE(aead_open(key, nonce, "short").has_value());  // < 16-byte MAC
  EXPECT_FALSE(aead_open(key, nonce, "").has_value());
}

TEST(Aead, SharedKeyDistinctNoncesBothOpen) {
  // The file-store pattern: one derived key, a distinct nonce per entry.
  Secret key = derive_key("pw", random_bytes(kSaltSize));
  std::string n1 = random_bytes(kNonceSize);
  std::string n2 = random_bytes(kNonceSize);
  std::string e1 = aead_seal(key, n1, "value-one");
  std::string e2 = aead_seal(key, n2, "value-two");
  EXPECT_EQ(aead_open(key, n1, e1)->view(), "value-one");
  EXPECT_EQ(aead_open(key, n2, e2)->view(), "value-two");
}
