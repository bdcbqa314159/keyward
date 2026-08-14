#include "keyward/windows_credential_store.hpp"

#if defined(_WIN32)

// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on

#include <cwchar>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
  const int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                                       static_cast<int>(s.size()), nullptr, 0);
  if (need <= 0) throw std::runtime_error("keyward: invalid UTF-8 in credential target name");
  std::wstring w(static_cast<size_t>(need), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(),
                      need);
  return w;
}

// UTF-16 -> UTF-8, for a NUL-terminated wide string (e.g. an enumerated target
// name). Returns empty on a null/empty input or a conversion failure.
std::string fromWide(const wchar_t* w) {
  if (w == nullptr) return {};
  const int len = static_cast<int>(std::wcslen(w));
  if (len == 0) return {};
  const int need = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
  if (need <= 0) return {};
  std::string s(static_cast<size_t>(need), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), need, nullptr, nullptr);
  return s;
}

// A Win32 error code rendered "error N: <system message>" for diagnostics.
// FormatMessage's text never contains our secret value, only an OS description.
// Falls back to just the numeric code if the message can't be formatted.
std::string errorText(DWORD err) {
  std::string out = "error " + std::to_string(err);
  LPWSTR buf = nullptr;
  const DWORD n = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buf), 0,
      nullptr);
  if (n != 0 && buf != nullptr) {
    std::wstring w(buf, n);
    while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n')) w.pop_back();  // trim CRLF
    if (!w.empty()) {
      const int bytes = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                            nullptr, 0, nullptr, nullptr);
      if (bytes > 0) {
        std::string msg(static_cast<size_t>(bytes), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), msg.data(), bytes,
                            nullptr, nullptr);
        out += ": " + msg;
      }
    }
  }
  if (buf != nullptr) LocalFree(buf);
  return out;
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
    throw std::runtime_error("keyward: CredReadW failed for '" + name + "' (" + errorText(err) +
                             ")");
  }
  // We own pcred now — copy the counted blob out (embedded NULs and all).
  std::string out(reinterpret_cast<const char*>(pcred->CredentialBlob),
                  static_cast<size_t>(pcred->CredentialBlobSize));
  // Scrub the plaintext from the OS-allocated buffer before freeing: CredFree
  // only releases the memory, it does not zero it, so the secret would otherwise
  // linger in freed heap. SecureZeroMemory is not optimized away.
  if (pcred->CredentialBlob != nullptr && pcred->CredentialBlobSize != 0)
    SecureZeroMemory(pcred->CredentialBlob, pcred->CredentialBlobSize);
  CredFree(pcred);
  return out;
}

void WindowsCredentialStore::set(const std::string& name, const std::string& value) {
  // Fail closed on oversize: never truncate, never downgrade to a file. Credential
  // Manager caps a generic blob at CRED_MAX_CREDENTIAL_BLOB_SIZE (2560 bytes) —
  // large tokens (some JWTs, PEM keys) can exceed this. The message carries name +
  // size only, never the secret value.
  if (value.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
    throw std::length_error("keyward: secret '" + name + "' is " + std::to_string(value.size()) +
                            " bytes, over the Windows Credential Manager blob limit of " +
                            std::to_string(CRED_MAX_CREDENTIAL_BLOB_SIZE) + " bytes");
  }
  const std::wstring target = toWide(targetName(app_, name));
  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  // Win32 takes a non-const LPBYTE but only reads it during the call.
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
  // Shown when a user browses "Windows Credentials" in Control Panel — never a secret.
  cred.Comment = const_cast<LPWSTR>(L"managed by keyward");
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteW(&cred, 0)) {  // upsert: replaces any existing item with this target
    throw std::runtime_error("keyward: CredWriteW failed for '" + name + "' (" +
                             errorText(GetLastError()) + ")");
  }
}

void WindowsCredentialStore::remove(const std::string& name) {
  const std::wstring target = toWide(targetName(app_, name));
  if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
    const DWORD err = GetLastError();
    if (err == ERROR_NOT_FOUND) return;  // surgical & idempotent: missing name is a no-op
    throw std::runtime_error("keyward: CredDeleteW failed for '" + name + "' (" + errorText(err) +
                             ")");
  }
}

std::vector<std::string> WindowsCredentialStore::list() {
  // Enumerate only our own items via the wildcard filter "keyward:<app>:*",
  // then strip the namespace prefix to recover the caller's names.
  const std::string prefix = targetName(app_, "");  // "keyward:<app>:"
  const std::wstring filter = toWide(prefix + "*");
  DWORD count = 0;
  PCREDENTIALW* creds = nullptr;
  if (!CredEnumerateW(filter.c_str(), 0, &count, &creds)) {
    const DWORD err = GetLastError();
    if (err == ERROR_NOT_FOUND) return {};  // no matching credentials — an empty store
    throw std::runtime_error("keyward: CredEnumerateW failed (" + errorText(err) + ")");
  }
  std::vector<std::string> names;
  names.reserve(count);
  for (DWORD i = 0; i < count; ++i) {
    const std::string target = fromWide(creds[i]->TargetName);
    if (target.starts_with(prefix)) names.push_back(target.substr(prefix.size()));
  }
  CredFree(creds);
  return names;
}

}  // namespace keyward

#endif  // _WIN32
