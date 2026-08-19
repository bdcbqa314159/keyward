#pragma once
#include <string>
#include <string_view>

#include "keyward/authenticator.hpp"

namespace keyward {

// Linux's answer to Touch ID and Windows Hello. macOS and Windows both ship a
// user-presence check keyward can call; Linux has no equivalent primitive, so it
// borrows the desktop's authorization broker — polkit — and lets the system
// policy decide whether reading a secret needs a password, a fingerprint (via a
// PAM-backed agent), or nothing at all.
//
// The guard is two conditions, for the same reason libsecret's is: polkit does
// not ship with every Linux, so `__linux__` alone proves nothing. CMake pkg-checks
// `polkit-gobject-1` and defines KEYWARD_HAVE_POLKIT only when it is present.
#if defined(__linux__) && defined(KEYWARD_HAVE_POLKIT)

// The action keyward asks about. polkit refuses to reason about actions it does
// not know, so this id must be registered by installing
// `packaging/com.keyward.policy` into /usr/share/polkit-1/actions/. Without it,
// the authenticator reports Unavailable rather than Denied — see below.
inline constexpr const char* kPolkitActionId = "com.keyward.access-secret";

// True when a polkit authority is reachable AND kPolkitActionId is registered —
// i.e. when a question could actually be asked. Mirrors biometric_available().
bool polkit_available();

// Asks polkit whether this process may access a secret.
//
// The Allowed/Denied/Unavailable/Cancelled mapping is the whole design, because
// FallbackAuthenticator only falls through on **Unavailable**. So "we could not
// ask" and "the user said no" must not be confused: the first has to degrade to
// the passphrase tier, the second must stand.
//
//   no authority (no system bus, no polkitd)   -> Unavailable
//   action id not registered (policy missing)  -> Unavailable  ("cannot ask")
//   authorized                                 -> Allowed
//   challenge required but unanswerable        -> Unavailable  (no agent present)
//   user declined / explicitly not authorized  -> Denied
//   the interaction was cancelled              -> Cancelled
class PolkitAuthenticator : public Authenticator {
 public:
  // `allow_interaction` false makes this a silent check — useful for deciding
  // whether to offer the tier at all without putting a dialog in front of anyone.
  explicit PolkitAuthenticator(bool allow_interaction = true);
  Authorization authorize(std::string_view service, std::string_view reason) override;

 private:
  bool allow_interaction_;
};

#endif  // __linux__ && KEYWARD_HAVE_POLKIT

}  // namespace keyward
