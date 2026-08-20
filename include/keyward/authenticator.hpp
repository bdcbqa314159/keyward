#pragma once
#include <string_view>

namespace keyward {

// Result of an access-time authorization check. Only Allowed releases a secret;
// everything else fails closed.
// The four answers an authenticator may give. The distinction between Denied and
// Unavailable is LOAD-BEARING and is the single easiest thing to get wrong:
//
//   Allowed      the user (or policy) approved — release the secret.
//   Denied       the user or policy REFUSED. A real "no". Respect it.
//   Cancelled    the user dismissed the prompt. Also denies access, but kept
//                separate so a caller can tell "no" from "not now".
//   Unavailable  the mechanism could not ASK AT ALL — no hardware, no enrolled
//                credential, no agent running, no policy installed, backend
//                unreachable.
//
// Only Unavailable lets FallbackAuthenticator try the next tier. An
// authenticator that returns Denied when it means "I could not ask" therefore
// strands the user with no way forward: the passphrase tier behind it never
// runs. Returning Unavailable when the user actually said no is the opposite
// error — it lets a weaker tier override a refusal.
enum class Authorization { Allowed, Denied, Cancelled, Unavailable };

// The access-time gate consulted before a stored secret is released. An
// implementation proves the user authorizes access — passphrase, biometric,
// agent, .... See docs/AUTHENTICATOR.md.
class Authenticator {
 public:
  virtual ~Authenticator() = default;
  // `service` is the record being accessed; `reason` is a human-readable verb
  // (e.g. "read"). Both are safe to display; neither is secret.
  //
  // THIS CONTRACT IS NOT NEGOTIABLE, and conformance is checkable — see
  // keyward/testing/conformance.hpp.
  //
  // An implementation MUST:
  //  1. Return Unavailable — never Denied — when it could not ask. See the enum
  //     above; this is what keeps a fallback tier reachable.
  //  2. Return Unavailable on an internal error too. The question went unasked,
  //     so a weaker tier may still ask it.
  //  3. Not throw. Map every failure onto one of the four values.
  //  4. Never include secret material in anything it displays or logs.
  //  5. Be safe to call repeatedly, and give a fresh answer each time unless it
  //     is deliberately caching (see CachingAuthenticator).
  //
  // An implementation MAY block while it asks the user.
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
