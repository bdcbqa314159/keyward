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

// Argon2id cost, in one place. nb_blocks is counted in KiB, so the work buffer
// must be exactly kArgonBlocks * 1024 bytes — one parameter, not two. It used to
// be the bare literal 100000 in four spots that silently had to agree.
#if defined(KEYWARD_FUZZ_CHEAP_KDF)
// FUZZ BUILDS ONLY — never defined by a normal configure. See the guard in
// CMakeLists.txt: this is set only inside if(KEYWARD_BUILD_FUZZERS), which also
// refuses to coexist with the test suite in one build tree.
//
// At production cost, unseal() runs Argon2id over 100 MB for every input past
// the 56-byte header: 12 executions in 21 seconds, which is not fuzzing. The KDF
// cost is orthogonal to what the fuzzer explores — the header parse, the length
// arithmetic and the AEAD verify are the same branches either way — so lowering
// it changes throughput, not coverage. 8 blocks is Monocypher's minimum.
#warning "KEYWARD_FUZZ_CHEAP_KDF: token Argon2 cost. FUZZING ONLY — never ship this build."
constexpr uint32_t kArgonBlocks = 8;
constexpr uint32_t kArgonPasses = 1;
#else
constexpr uint32_t kArgonBlocks = 100000;  // 100 MB of work memory
constexpr uint32_t kArgonPasses = 3;
#endif
constexpr uint32_t kArgonLanes = 1;
constexpr std::size_t kWorkBytes = static_cast<std::size_t>(kArgonBlocks) * 1024;
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

  std::vector<uint8_t> work(kWorkBytes);
  std::vector<uint8_t> cipher(plaintext.size());

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, kArgonBlocks, kArgonPasses, kArgonLanes};
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

std::optional<Secret> unseal(std::string_view blob, std::string_view passphrase) {
  constexpr std::size_t kHeader = 56;  // 16 + 24 + 16
  constexpr std::size_t kSaltSize = 16;

  if (blob.size() < kHeader) return std::nullopt;

  const uint8_t* salt = u8(blob) + 0;
  const uint8_t* nonce = u8(blob) + 16;
  const uint8_t* mac = u8(blob) + 40;
  const uint8_t* cipher = u8(blob) + 56;

  std::size_t cipher_size = blob.size() - kHeader;

  std::vector<uint8_t> work(kWorkBytes);

  constexpr std::size_t kKeySize = 32;
  std::unique_ptr<unsigned char, void (*)(void*)> key(
      static_cast<unsigned char*>(secure_alloc(kKeySize)), &secure_free);

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, kArgonBlocks, kArgonPasses, kArgonLanes};
  crypto_argon2_inputs in{u8(passphrase), salt, static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(kSaltSize)};
  crypto_argon2(key.get(), kKeySize, work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  std::vector<uint8_t> out(cipher_size);
  int rc = crypto_aead_unlock(out.data(), mac, key.get(), nonce, nullptr, 0, cipher, cipher_size);
  // key auto-zeroed + freed on scope exit — including this early-return path
  if (rc != 0) return std::nullopt;
  // Copy the recovered plaintext into secure memory, then wipe the plain buffer.
  Secret plaintext(std::string_view(reinterpret_cast<const char*>(out.data()), cipher_size));
  crypto_wipe(out.data(), out.size());
  return plaintext;
}

}  // namespace keyward
