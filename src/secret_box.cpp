#include "keyward/secret_box.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "keyward/random.hpp"
#include "keyward/secure_memory.hpp"
#include "monocypher.h"

namespace keyward {

namespace {
const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }
}  // namespace

std::string seal(std::string_view plaintext, std::string_view passphrase) {
  std::string salt = random_bytes(16);
  std::string nonce = random_bytes(24);

  constexpr std::size_t kKeySize = 32;
  // Derived key in libsodium secure memory (guard-paged, mlock'd, auto-zeroed by
  // secure_free at scope end) instead of a swappable stack buffer.
  std::unique_ptr<unsigned char, void (*)(void*)> key(
      static_cast<unsigned char*>(secure_alloc(kKeySize)), &secure_free);
  uint8_t mac[16] = {};

  std::vector<uint8_t> work(static_cast<std::size_t>(1024) * 100000);
  std::vector<uint8_t> cipher(plaintext.size());

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, 100000, 3, 1};
  crypto_argon2_inputs in{u8(passphrase), u8(salt), static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(salt.size())};

  crypto_argon2(key.get(), kKeySize, work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  crypto_aead_lock(cipher.data(), mac, key.get(), u8(nonce), nullptr, 0, u8(plaintext),
                   plaintext.size());

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

  constexpr std::size_t kKeySize = 32;
  std::unique_ptr<unsigned char, void (*)(void*)> key(
      static_cast<unsigned char*>(secure_alloc(kKeySize)), &secure_free);

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, 100000, 3, 1};
  crypto_argon2_inputs in{u8(passphrase), salt, static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(kSaltSize)};
  crypto_argon2(key.get(), kKeySize, work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  std::vector<uint8_t> out(cipher_size);
  int rc = crypto_aead_unlock(out.data(), mac, key.get(), nonce, nullptr, 0, cipher, cipher_size);
  // key auto-zeroed + freed on scope exit — including this early-return path
  if (rc != 0) return std::nullopt;
  return std::string(reinterpret_cast<const char*>(out.data()), cipher_size);
}

}  // namespace keyward
