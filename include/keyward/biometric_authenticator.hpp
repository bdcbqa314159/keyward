#pragma once
#include <string>
#include <string_view>

#include "keyward/authenticator.hpp"

namespace keyward {

// Compile-time: is a biometric backend built in for this platform? (macOS Touch
// ID today.) When false, BiometricAuthenticator::authorize always returns
// Unavailable — so callers can fall back to a passphrase.
bool biometric_available();

// An Authenticator backed by the platform biometric prompt (macOS Touch ID via
// LocalAuthentication). authorize() returns:
//   Allowed     - biometric succeeded
//   Cancelled   - user dismissed the prompt
//   Denied      - biometric failed (e.g. unrecognised)
//   Unavailable - no biometric backend / no enrolled biometric / no hardware
// A Vault typically wraps this with a passphrase fallback on Unavailable.
class BiometricAuthenticator : public Authenticator {
 public:
  // `reason` shown in the OS prompt is built from the service + the verb passed
  // to authorize(); `fallback_title` is the OS "enter password instead" button
  // label (empty hides it where the platform allows).
  explicit BiometricAuthenticator(std::string fallback_title = "");
  Authorization authorize(std::string_view service, std::string_view reason) override;

 private:
  std::string fallback_title_;
};

}  // namespace keyward
