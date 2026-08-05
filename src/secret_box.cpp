#include "keyward/secret_box.hpp"

#include <Security/cssmconfig.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "keyward/random.hpp"
#include "monocypher.h"

namespace keyward {

namespace {
const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }
}  // namespace

std::string seal(std::string_view plaintext, std::string_view passphrase) {
  std::string salt = random_bytes(16);
  std::string nonce = random_bytes(24);

  uint8_t key[32] = {};
  uint8_t mac[16] = {};

  std::vector<uint8_t> work(static_cast<std::size_t>(1024) * 100000);
  std::vector<uint8_t> cipher(plaintext.size());

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, 100000, 3, 1};
  crypto_argon2_inputs in{u8(passphrase), u8(salt), static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(salt.size())};

  crypto_argon2(key, sizeof(key), work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  crypto_aead_lock(cipher.data(), mac, key, u8(nonce), nullptr, 0, u8(plaintext), plaintext.size());
  crypto_wipe(key, 32);

  std::string mac_string = std::string(reinterpret_cast<const char*>(mac), 16);
  std::string cipher_string =
      std::string(reinterpret_cast<const char*>(cipher.data()), plaintext.size());

  return salt + nonce + mac_string + cipher_string;
}

std::optional<std::string> unseal(std::string_view blob, std::string_view passphrase) {
  constexpr std::size_t kHeader = 56;  // 16 + 24 + 16
  constexpr std::size_t kSaltSize = 16;

  if (blob.size() < kHeader) return std::nullopt;

  const uint8_t* salt = u8(blob) + 0;
  const uint8_t* nonce = u8(blob) + 16;
  const uint8_t* mac = u8(blob) + 40;
  const uint8_t* cipher = u8(blob) + 56;

  std::size_t cipher_size = blob.size() - kHeader;

  std::vector<uint8_t> work(static_cast<std::size_t>(1024) * 100000);

  uint8_t key[32] = {};

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, 100000, 3, 1};
  crypto_argon2_inputs in{u8(passphrase), salt, static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(16)};
  crypto_argon2(key, sizeof(key), work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  std::vector<uint8_t> out(cipher_size);
  int rc = crypto_aead_unlock(out.data(), mac, key, nonce, nullptr, 0, cipher, cipher_size);
  crypto_wipe(key, sizeof(key));
  if (rc != 0) return std::nullopt;
  return std::string(reinterpret_cast<const char*>(out.data()), cipher_size);
}

}  // namespace keyward
