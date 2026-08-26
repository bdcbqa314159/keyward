#pragma once
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "keyward/authenticator.hpp"

namespace keyward {

// Create a verifier blob (cost-profile version + salt + Argon2id hash) for
// `passphrase`. Store it — in the vault, a file, wherever — at setup time, then
// feed it back to a PassphraseAuthenticator. It reveals nothing about the
// passphrase. Throws std::invalid_argument on an empty passphrase.
std::string make_passphrase_verifier(std::string_view passphrase);

// Check `passphrase` against a verifier from make_passphrase_verifier, in
// constant time. false on mismatch or a malformed verifier.
bool verify_passphrase(std::string_view passphrase, std::string_view verifier);

// Gathers a passphrase (masked). Returns the entered value, or std::nullopt to
// cancel. A CLI wires this to no-echo terminal input; tests wire a lambda. Kept
// separate from Prompter (which gathers credential *fields*, not an unlock).
using PassphraseSource = std::function<std::optional<std::string>(std::string_view prompt)>;

// An Authenticator that unlocks on a correct passphrase. Prompts up to
// `max_attempts` times: Allowed on a match, Cancelled if the source cancels,
// Denied once the attempts are exhausted.
class PassphraseAuthenticator : public Authenticator {
 public:
  PassphraseAuthenticator(std::string verifier, PassphraseSource source, int max_attempts = 3);
  Authorization authorize(std::string_view service, std::string_view reason) override;

 private:
  std::string verifier_;
  PassphraseSource source_;
  int max_attempts_;
};

}  // namespace keyward
