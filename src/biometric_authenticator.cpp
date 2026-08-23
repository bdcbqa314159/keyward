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

#elif defined(_WIN32)

// ---- Windows Hello, via C++/WinRT UserConsentVerifier -------------------------
//
// The Windows analogue of macOS Touch ID. UserConsentVerifier is the WinRT API
// that raises the Hello prompt (face / fingerprint / PIN) and reports whether the
// present user proved it. It ships with the Windows SDK; C++/WinRT is header-only,
// so the only build cost is linking the WinRT activation runtime — RuntimeObject
// (see CMakeLists) — for RoGetActivationFactory. No fetched dependency.
//
// Two Windows-specific gotchas drive the shape of this file:
//
//  1. NO CoreWindow. UserConsentVerifier::RequestVerificationAsync() (the plain
//     WinRT method) needs a CoreWindow, which an unpackaged Win32/console process
//     does not have — it fails at runtime. The supported path for classic desktop
//     apps is the COM interop interface IUserConsentVerifierInterop, whose
//     RequestVerificationForWindowAsync() takes an HWND to parent the prompt on.
//     We hand it the console window (or the foreground window); with no window at
//     all we cannot show UI, which is "cannot ask" -> Unavailable (fail closed).
//
//  2. Apartment + blocking. The Hello UI is hosted OUT OF PROCESS by
//     CredentialUIBroker and parented to our HWND, so the calling thread does not
//     itself pump the dialog. We run the exchange on our own dedicated
//     multi-threaded-apartment (MTA) thread and block on the async with .get():
//     .get() on an STA thread deadlocks (it blocks the very thread that would have
//     to pump), whereas on an MTA thread it is the correct, supported wait. Using
//     our own thread also means we never disturb the caller's COM state, and the
//     join is the synchronisation barrier.

// clang-format off
#include <windows.h>
#include <unknwn.h>
#include <UserConsentVerifierInterop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
// clang-format on

#include <thread>

namespace keyward {
namespace {

using namespace winrt::Windows::Security::Credentials::UI;

// The window to parent the Hello prompt on. A console app has GetConsoleWindow();
// a GUI/TUI host has a foreground window. nullptr means we have nowhere to show
// the prompt — the caller must treat that as "could not ask".
HWND promptWindow() {
  if (HWND h = GetConsoleWindow()) return h;
  return GetForegroundWindow();
}

// Run `fn` on a dedicated MTA thread and return. We must not init_apartment on the
// caller's thread — that throws RPC_E_CHANGED_MODE if they already chose a
// different model, and would leave their thread in an apartment we picked. Our own
// thread is ours to initialise; MTA lets us block on the async with .get() without
// the STA deadlock (see the header comment). join is the barrier.
template <typename Fn>
void runOnComThread(Fn&& fn) {
  std::thread worker([&] {
    try {
      winrt::init_apartment(winrt::apartment_type::multi_threaded);
      fn();
    } catch (...) {
      // fn is responsible for having set a fail-closed default before it can throw.
    }
  });
  worker.join();
}

}  // namespace

bool biometric_available() {
  bool available = false;
  runOnComThread([&] {
    available = UserConsentVerifier::CheckAvailabilityAsync().get() ==
                UserConsentVerifierAvailability::Available;
  });
  return available;  // stays false on any throw — fail closed
}

BiometricAuthenticator::BiometricAuthenticator(std::string fallback_title)
    : fallback_title_(std::move(fallback_title)) {}

Authorization BiometricAuthenticator::authorize(std::string_view service, std::string_view reason) {
  const HWND hwnd = promptWindow();
  if (hwnd == nullptr) return Authorization::Unavailable;  // nowhere to show the prompt

  // Message shown in the Hello dialog: "<reason> <service>". Never a secret.
  const std::string prompt = std::string(reason) + " " + std::string(service);

  // Run the UI exchange on a dedicated COM thread (see runOnComThread). `result`
  // defaults to the fail-closed Unavailable and is only raised on a real answer.
  Authorization result = Authorization::Unavailable;
  runOnComThread([&] {
    // The interop factory bridges the runtime class to the HWND-taking method.
    auto interop =
        winrt::get_activation_factory<UserConsentVerifier, ::IUserConsentVerifierInterop>();
    const winrt::hstring message = winrt::to_hstring(prompt);

    winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult> op{nullptr};
    const HRESULT hr = interop->RequestVerificationForWindowAsync(
        hwnd, reinterpret_cast<HSTRING>(winrt::get_abi(message)),
        winrt::guid_of<
            winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult> >(),
        winrt::put_abi(op));
    if (FAILED(hr) || op == nullptr) return;  // could not start the prompt -> Unavailable

    switch (op.get()) {
      case UserConsentVerificationResult::Verified:
        result = Authorization::Allowed;
        break;
      case UserConsentVerificationResult::Canceled:
        result = Authorization::Cancelled;
        break;
      case UserConsentVerificationResult::RetriesExhausted:
        // The user was asked and failed to prove presence — a real "no".
        result = Authorization::Denied;
        break;
      // DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy / DeviceBusy:
      // the question could not be asked -> degrade so a fallback tier can run.
      default:
        break;  // stays Unavailable
    }
  });
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
