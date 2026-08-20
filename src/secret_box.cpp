#include "keyward/secret_box.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "keyward/crypto_primitives.hpp"
#include "keyward/random.hpp"
#include "keyward/secure_memory.hpp"
#include "monocypher.h"

namespace keyward {

namespace {
const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }

// Argon2id cost, in one place. nb_blocks is counted in KiB, so the work buffer
// must be exactly kArgonBlocks * 1024 bytes — one parameter, not two.
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

// ---- low-level primitives (crypto_primitives.hpp) -------------------------

Secret derive_key(std::string_view passphrase, std::string_view salt) {
  // Argon2id into a secure scratch buffer, then wrap in a Secret. Both the
  // scratch and the work area are wiped/freed before returning.
  std::unique_ptr<unsigned char, void (*)(void*)> raw(
      static_cast<unsigned char*>(secure_alloc(kKeySize)), &secure_free);
  std::vector<uint8_t> work(kWorkBytes);

  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, kArgonBlocks, kArgonPasses, kArgonLanes};
  crypto_argon2_inputs in{u8(passphrase), u8(salt), static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(salt.size())};
  crypto_argon2(raw.get(), kKeySize, work.data(), cfg, in, crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());

  return Secret(std::string_view(reinterpret_cast<const char*>(raw.get()), kKeySize));
}

std::string aead_seal(const Secret& key, std::string_view nonce, std::string_view plaintext) {
  uint8_t mac[kMacSize] = {};
  std::vector<uint8_t> cipher(plaintext.size());
  crypto_aead_lock(cipher.data(), mac, u8(key.view()), u8(nonce), nullptr, 0, u8(plaintext),
                   plaintext.size());
  std::string out;
  out.reserve(kMacSize + cipher.size());
  out.append(reinterpret_cast<const char*>(mac), kMacSize);
  out.append(reinterpret_cast<const char*>(cipher.data()), cipher.size());
  return out;
}

std::optional<Secret> aead_open(const Secret& key, std::string_view nonce,
                                std::string_view sealed) {
  if (sealed.size() < kMacSize) return std::nullopt;
  const uint8_t* mac = u8(sealed);
  const uint8_t* cipher = u8(sealed) + kMacSize;
  std::size_t cipher_size = sealed.size() - kMacSize;

  std::vector<uint8_t> out(cipher_size);
  int rc = crypto_aead_unlock(out.data(), mac, u8(key.view()), u8(nonce), nullptr, 0, cipher,
                              cipher_size);
  if (rc != 0) return std::nullopt;  // wrong key/nonce or tampered
  Secret plaintext(std::string_view(reinterpret_cast<const char*>(out.data()), cipher_size));
  crypto_wipe(out.data(), out.size());
  return plaintext;
}

// ---- one-shot convenience (secret_box.hpp) --------------------------------

std::string seal(std::string_view plaintext, std::string_view passphrase) {
  std::string salt = random_bytes(kSaltSize);
  std::string nonce = random_bytes(kNonceSize);
  Secret key = derive_key(passphrase, salt);
  return salt + nonce + aead_seal(key, nonce, plaintext);  // salt ‖ nonce ‖ (mac ‖ cipher)
}

std::optional<Secret> unseal(std::string_view blob, std::string_view passphrase) {
  constexpr std::size_t kPrefix = kSaltSize + kNonceSize;  // salt + nonce; mac lives in `sealed`
  if (blob.size() < kPrefix + kMacSize) return std::nullopt;

  std::string_view salt = blob.substr(0, kSaltSize);
  std::string_view nonce = blob.substr(kSaltSize, kNonceSize);
  std::string_view sealed = blob.substr(kPrefix);  // mac ‖ cipher

  Secret key = derive_key(passphrase, salt);
  return aead_open(key, nonce, sealed);
}

}  // namespace keyward
