#include "keyward/biometric_authenticator.hpp"

#include <string>

#if defined(__APPLE__)

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>

namespace keyward {

bool biometric_available() {
  LAContext* ctx = [[LAContext alloc] init];
  BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
  return ok == YES;
}

BiometricAuthenticator::BiometricAuthenticator(std::string fallback_title)
    : fallback_title_(std::move(fallback_title)) {}

Authorization BiometricAuthenticator::authorize(std::string_view service, std::string_view reason) {
  LAContext* ctx = [[LAContext alloc] init];
  if (!fallback_title_.empty()) {
    ctx.localizedFallbackTitle = [NSString stringWithUTF8String:fallback_title_.c_str()];
  }

  NSError* err = nil;
  if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&err]) {
    return Authorization::Unavailable;  // no hardware / not enrolled
  }

  // LAContext evaluates asynchronously; block until the prompt resolves. Build
  // the human-readable reason the OS shows: "<reason> <service>".
  std::string prompt = std::string(reason) + " " + std::string(service);
  NSString* nsReason = [NSString stringWithUTF8String:prompt.c_str()];

  __block Authorization result = Authorization::Denied;
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
      localizedReason:nsReason
                reply:^(BOOL success, NSError* e) {
                  if (success) {
                    result = Authorization::Allowed;
                  } else if (e.code == LAErrorUserCancel || e.code == LAErrorSystemCancel ||
                             e.code == LAErrorAppCancel) {
                    result = Authorization::Cancelled;
                  } else {
                    result = Authorization::Denied;
                  }
                  dispatch_semaphore_signal(done);
                }];
  dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  return result;
}

}  // namespace keyward

#else  // ---- no biometric backend on this platform ----

namespace keyward {

bool biometric_available() { return false; }

BiometricAuthenticator::BiometricAuthenticator(std::string fallback_title)
    : fallback_title_(std::move(fallback_title)) {}

Authorization BiometricAuthenticator::authorize(std::string_view /*service*/,
                                                std::string_view /*reason*/) {
  return Authorization::Unavailable;
}

}  // namespace keyward

#endif
