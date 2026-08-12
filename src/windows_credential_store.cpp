#include "keyward/windows_credential_store.hpp"

#if defined(_WIN32)

// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on

#include <stdexcept>
#include <string>
#include <utility>

namespace keyward {
namespace {

// Namespaced target name (still UTF-8 here; convert to UTF-16 at the API edge).
std::string targetName(const std::string& app, const std::string& name) {
  return "keyward:" + app + ":" + name;
}

// UTF-8 std::string -> UTF-16 std::wstring. Used only for the *target name* (a
// string); the credential blob stays raw bytes and is never converted.
// Two-call idiom: size first (cchWideChar == 0), then fill. We pass the exact
// byte count (not -1) so no terminating NUL is counted into the length; the
// std::wstring is NUL-terminated by c_str() at the call site.
std::wstring toWide(const std::string& s) {
  if (s.empty()) return std::wstring();
  const int need =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()),
                          nullptr, 0);
  if (need <= 0) throw std::runtime_error("keyward: invalid UTF-8 in credential target name");
  std::wstring w(static_cast<size_t>(need), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(),
                      need);
  return w;
}

}  // namespace

WindowsCredentialStore::WindowsCredentialStore(std::string app) : app_(std::move(app)) {}

std::optional<std::string> WindowsCredentialStore::get(const std::string& name) {
  const std::wstring target = toWide(targetName(app_, name));
  PCREDENTIALW pcred = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred)) {
    const DWORD err = GetLastError();
    if (err == ERROR_NOT_FOUND) return std::nullopt;  // a genuine miss
    // Fail closed on any other error rather than masking it as "not found".
    throw std::runtime_error("keyward: CredReadW failed for '" + name + "' (error " +
                             std::to_string(err) + ")");
  }
  // We own pcred now — copy the counted blob out (embedded NULs and all), then free.
  std::string out(reinterpret_cast<const char*>(pcred->CredentialBlob),
                  static_cast<size_t>(pcred->CredentialBlobSize));
  CredFree(pcred);
  return out;
}

void WindowsCredentialStore::set(const std::string& name, const std::string& value) {
  // Fail closed on oversize: never truncate, never downgrade to a file. The
  // message carries name + size only — never the secret value.
  if (value.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
    throw std::length_error("keyward: secret '" + name + "' is " + std::to_string(value.size()) +
                            " bytes, over the Credential Manager limit of " +
                            std::to_string(CRED_MAX_CREDENTIAL_BLOB_SIZE));
  }
  const std::wstring target = toWide(targetName(app_, name));
  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  // Win32 takes a non-const LPBYTE but only reads it during the call.
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteW(&cred, 0)) {  // upsert: replaces any existing item with this target
    throw std::runtime_error("keyward: CredWriteW failed for '" + name + "' (error " +
                             std::to_string(GetLastError()) + ")");
  }
}

void WindowsCredentialStore::remove(const std::string& name) {
  const std::wstring target = toWide(targetName(app_, name));
  if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
    const DWORD err = GetLastError();
    if (err == ERROR_NOT_FOUND) return;  // surgical & idempotent: missing name is a no-op
    throw std::runtime_error("keyward: CredDeleteW failed for '" + name + "' (error " +
                             std::to_string(err) + ")");
  }
}

}  // namespace keyward

#endif  // _WIN32
