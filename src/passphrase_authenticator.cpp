#include "keyward/passphrase_authenticator.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "keyward/random.hpp"
#include "keyward/secret.hpp"
#include "keyward/secure_memory.hpp"
#include "monocypher.h"

namespace keyward {
namespace {

constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kHashSize = 32;

// M3: the verifier blob (`version ‖ salt ‖ hash`) is meant to be stored at rest,
// so its Argon2id cost must sit at the offline-cracking floor, not a snappy
// minimum. The leading version byte names the cost profile the hash was made
// with, so a later cost bump can raise kCurrentProfile without invalidating
// already-stored verifiers — verify() dispatches on the stored id.
struct CostProfile {
  uint8_t id;
  uint32_t blocks;  // Argon2 memory in KiB (1024-byte blocks)
  uint32_t passes;
};
// Profile 1: OWASP Argon2id floor — 19 MiB, t=2, p=1.
constexpr CostProfile kProfiles[] = {{1, 19456, 2}};
constexpr uint8_t kCurrentProfile = 1;

const CostProfile* findProfile(uint8_t id) {
  for (const auto& p : kProfiles)
    if (p.id == id) return &p;
  return nullptr;
}

const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }

// Argon2id(passphrase, salt) -> kHashSize bytes, at the given cost profile.
std::string argon2_hash(std::string_view passphrase, std::string_view salt, const CostProfile& cp) {
  std::vector<uint8_t> work(static_cast<std::size_t>(1024) * cp.blocks);
  std::string hash(kHashSize, '\0');
  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, cp.blocks, cp.passes, 1};
  crypto_argon2_inputs in{u8(passphrase), u8(salt), static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(salt.size())};
  crypto_argon2(reinterpret_cast<uint8_t*>(hash.data()), kHashSize, work.data(), cfg, in,
                crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());
  return hash;
}

}  // namespace

std::string make_passphrase_verifier(std::string_view passphrase) {
  if (passphrase.empty())  // L3: no verifier that unlocks on "" — reject weak enrollment
    throw std::invalid_argument("keyward: refusing to enroll an empty passphrase");
  const CostProfile& cp = *findProfile(kCurrentProfile);
  std::string salt = random_bytes(kSaltSize);
  std::string out(1, static_cast<char>(cp.id));  // version ‖ salt ‖ hash
  out += salt;
  out += argon2_hash(passphrase, salt, cp);
  return out;
}

bool verify_passphrase(std::string_view passphrase, std::string_view verifier) {
  if (verifier.size() != 1 + kSaltSize + kHashSize) return false;
  const CostProfile* cp = findProfile(static_cast<uint8_t>(verifier[0]));
  if (cp == nullptr) return false;  // unknown cost profile -> can't reproduce the hash
  std::string got = argon2_hash(passphrase, verifier.substr(1, kSaltSize), *cp);
  bool ok = secure_equal(got.data(), verifier.data() + 1 + kSaltSize, kHashSize);
  secure_zero(got.data(), got.size());
  return ok;
}

PassphraseAuthenticator::PassphraseAuthenticator(std::string verifier, PassphraseSource source,
                                                 int max_attempts)
    : verifier_(std::move(verifier)), source_(std::move(source)), max_attempts_(max_attempts) {}

Authorization PassphraseAuthenticator::authorize(std::string_view service,
                                                 std::string_view reason) {
  for (int attempt = 0; attempt < max_attempts_; ++attempt) {
    std::string prompt = "Passphrase to " + std::string(reason) + " " + std::string(service) + ":";
    std::optional<std::string> entered = source_(prompt);
    if (!entered) return Authorization::Cancelled;
    // Hold the entered passphrase in secure memory; wipe the plain source copy.
    Secret secure_entered(*entered);
    secure_zero(entered->data(), entered->size());
    bool ok = verify_passphrase(secure_entered.view(), verifier_);
    if (ok) return Authorization::Allowed;
  }
  return Authorization::Denied;
}

}  // namespace keyward
