#pragma once
#include <string_view>

namespace keyward {

// Result of an access-time authorization check. Only Allowed releases a secret;
// everything else fails closed.
enum class Authorization { Allowed, Denied, Cancelled, Unavailable };

// The access-time gate consulted before a stored secret is released. An
// implementation proves the user authorizes access — passphrase, biometric,
// agent, .... See docs/AUTHENTICATOR.md.
class Authenticator {
 public:
  virtual ~Authenticator() = default;
  // `service` is the record being accessed; `reason` is a human-readable verb
  // (e.g. "read"). Return Allowed to release the secret.
  virtual Authorization authorize(std::string_view service, std::string_view reason) = 0;
};

// The default gate: always allows. This is today's behaviour — an explicit,
// named "no gate" rather than a silent absence.
class NoAuth : public Authenticator {
 public:
  Authorization authorize(std::string_view /*service*/, std::string_view /*reason*/) override {
    return Authorization::Allowed;
  }
};

}  // namespace keyward
