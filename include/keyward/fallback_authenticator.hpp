#pragma once
#include <memory>

#include "keyward/authenticator.hpp"

namespace keyward {

// Try `primary`; if it reports Unavailable, fall through to `fallback`. This is
// the "biometric if available, else passphrase" policy from AUTHENTICATOR.md —
// a denied/cancelled primary is respected (NOT downgraded), only Unavailable
// falls through.
class FallbackAuthenticator : public Authenticator {
 public:
  FallbackAuthenticator(std::unique_ptr<Authenticator> primary,
                        std::unique_ptr<Authenticator> fallback)
      : primary_(std::move(primary)), fallback_(std::move(fallback)) {}

  Authorization authorize(std::string_view service, std::string_view reason) override {
    Authorization a = primary_->authorize(service, reason);
    if (a == Authorization::Unavailable) return fallback_->authorize(service, reason);
    return a;
  }

 private:
  std::unique_ptr<Authenticator> primary_;
  std::unique_ptr<Authenticator> fallback_;
};

}  // namespace keyward
