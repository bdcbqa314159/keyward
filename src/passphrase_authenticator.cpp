#include "keyward/passphrase_authenticator.hpp"

#include <cstddef>
#include <cstdint>
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
// Access-gate cost — deliberately modest for a snappy unlock. Raise nb_blocks
// for stronger resistance if the verifier blob could be exfiltrated and cracked.
constexpr uint32_t kBlocks = 8192;  // 8 MiB
constexpr uint32_t kPasses = 3;

const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }

// Argon2id(passphrase, salt) -> kHashSize bytes.
std::string argon2_hash(std::string_view passphrase, std::string_view salt) {
  std::vector<uint8_t> work(static_cast<std::size_t>(1024) * kBlocks);
  std::string hash(kHashSize, '\0');
  crypto_argon2_config cfg{CRYPTO_ARGON2_ID, kBlocks, kPasses, 1};
  crypto_argon2_inputs in{u8(passphrase), u8(salt), static_cast<uint32_t>(passphrase.size()),
                          static_cast<uint32_t>(salt.size())};
  crypto_argon2(reinterpret_cast<uint8_t*>(hash.data()), kHashSize, work.data(), cfg, in,
                crypto_argon2_no_extras);
  crypto_wipe(work.data(), work.size());
  return hash;
}

}  // namespace

std::string make_passphrase_verifier(std::string_view passphrase) {
  std::string salt = random_bytes(kSaltSize);
  return salt + argon2_hash(passphrase, salt);  // salt ‖ hash
}

bool verify_passphrase(std::string_view passphrase, std::string_view verifier) {
  if (verifier.size() != kSaltSize + kHashSize) return false;
  std::string got = argon2_hash(passphrase, verifier.substr(0, kSaltSize));
  bool ok = secure_equal(got.data(), verifier.data() + kSaltSize, kHashSize);
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
