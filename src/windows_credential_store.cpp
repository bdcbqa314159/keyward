#include "keyward/windows_credential_store.hpp"

#if defined(_WIN32)

// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on

#include <algorithm>
#include <cwchar>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keyward {
namespace {

// Target-name scheme, chosen to interoperate with Python `keyring`'s Windows
// backend (WinVaultKeyring) so the two tools' items live in the same namespace.
// keyring maps (service, username) -> keyward's (app, name), and stores each
// secret under the COMPOUND target "<username>@<service>" once more than one
// username exists for a service (the newest sits at the bare "<service>", older
// ones are displaced to the compound form). keyward holds many names per app, so
// it always writes the compound form "<name>@<app>" — which keyring resolves via
// its own compound fallback — and reads the bare "<app>" too so it can see a
// secret keyring wrote as the newest-for-service.
//
// NOTE: this is a NAMESPACE alignment, not a value-format one. keyring encodes
// the blob as UTF-16-LE text; keyward stores raw bytes (its Vault records are
// binary). So the items are mutually discoverable, but a value only survives the
// crossing intact when it is UTF-16-LE — a plain keyward record is not readable
// as a keyring string, and vice versa. See docs/DESIGN.md.
std::string compoundTarget(const std::string& app, const std::string& name) {
  return name + "@" + app;  // keyring's "<username>@<service>"
}

// UTF-8 std::string -> UTF-16 std::wstring. Used only for the *target name* and
// the *username* (both strings); the credential blob stays raw bytes and is never
// converted. Two-call idiom: size first (cchWideChar == 0), then fill. We pass the
// exact byte count (not -1) so no terminating NUL is counted into the length; the
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
// name or a credential's UserName). Returns empty on a null/empty input or a
// conversion failure.
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

// What a single credential holds that keyward cares about: the UserName (keyward's
// `name`) and the raw blob. keyring stores the name in UserName, and so do we, so
// reads can tell a bare "<app>" item's owner apart.
struct CredData {
  std::string username;
  std::string blob;
};

// Read the credential at `target`. nullopt on a genuine miss (ERROR_NOT_FOUND);
// throws (fail closed) on any other error rather than masking it. `context` names
// the caller's item for the error message — never a secret.
std::optional<CredData> readCredential(const std::wstring& target, const std::string& context) {
  PCREDENTIALW pcred = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pcred)) {
    const DWORD err = GetLastError();
    if (err == ERROR_NOT_FOUND) return std::nullopt;
    throw std::runtime_error("keyward: CredReadW failed for '" + context + "' (" + errorText(err) +
                             ")");
  }
  CredData out;
  out.username = fromWide(pcred->UserName);
  out.blob.assign(reinterpret_cast<const char*>(pcred->CredentialBlob),
                  static_cast<size_t>(pcred->CredentialBlobSize));
  // Scrub the plaintext from the OS-allocated buffer before freeing: CredFree only
  // releases the memory, it does not zero it, so the secret would otherwise linger
  // in freed heap. SecureZeroMemory is not optimized away.
  if (pcred->CredentialBlob != nullptr && pcred->CredentialBlobSize != 0)
    SecureZeroMemory(pcred->CredentialBlob, pcred->CredentialBlobSize);
  CredFree(pcred);
  return out;
}

}  // namespace

WindowsCredentialStore::WindowsCredentialStore(std::string app) : app_(std::move(app)) {}

std::optional<std::string> WindowsCredentialStore::get(const std::string& name) {
  // keyward's own items live at the compound target; try that first so a keyward
  // write is authoritative for a keyward read.
  if (auto c = readCredential(toWide(compoundTarget(app_, name)), name)) return c->blob;
  // Fall back to the bare "<app>" target, which is where keyring parks the
  // newest-for-service secret — but only if its UserName is this name, mirroring
  // keyring's own (service, username) match. This is how keyward SEES a
  // keyring-written secret (its bytes are UTF-16-LE; see the scheme note above).
  if (auto c = readCredential(toWide(app_), name); c && c->username == name) return c->blob;
  return std::nullopt;
}

void WindowsCredentialStore::set(const std::string& name, std::string_view value) {
  // Fail closed on oversize: never truncate, never downgrade to a file. Credential
  // Manager caps a generic blob at CRED_MAX_CREDENTIAL_BLOB_SIZE (2560 bytes) —
  // large tokens (some JWTs, PEM keys) can exceed this. The message carries name +
  // size only, never the secret value.
  if (value.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
    throw std::length_error("keyward: secret '" + name + "' is " + std::to_string(value.size()) +
                            " bytes, over the Windows Credential Manager blob limit of " +
                            std::to_string(CRED_MAX_CREDENTIAL_BLOB_SIZE) + " bytes");
  }
  const std::wstring target = toWide(compoundTarget(app_, name));
  const std::wstring user = toWide(name);  // keyring's `username`; lets reads disambiguate
  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.UserName = user.empty() ? nullptr : const_cast<LPWSTR>(user.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  // Win32 takes a non-const LPBYTE but only reads it during the call. Blob stays
  // RAW BYTES (embedded NULs preserved) — keyward does not encode UTF-16-LE, so a
  // keyward record is not a keyring-readable string. See the scheme note above.
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
  // Shown when a user browses "Windows Credentials" in Control Panel — never a secret.
  cred.Comment = const_cast<LPWSTR>(L"managed by keyward");
  cred.Persist =
      CRED_PERSIST_LOCAL_MACHINE;  // keyring uses ENTERPRISE; Persist is not part of
                                   // the (target, username) key, so it does not affect
                                   // interop, and LOCAL_MACHINE keeps secrets off roaming.
  if (!CredWriteW(&cred, 0)) {     // upsert: replaces any existing item with this target
    throw std::runtime_error("keyward: CredWriteW failed for '" + name + "' (" +
                             errorText(GetLastError()) + ")");
  }
}

void WindowsCredentialStore::remove(const std::string& name) {
  bool removedAny = false;
  // The compound target is keyward's own; delete it if present.
  if (!CredDeleteW(toWide(compoundTarget(app_, name)).c_str(), CRED_TYPE_GENERIC, 0)) {
    const DWORD err = GetLastError();
    if (err != ERROR_NOT_FOUND)
      throw std::runtime_error("keyward: CredDeleteW failed for '" + name + "' (" + errorText(err) +
                               ")");
  } else {
    removedAny = true;
  }
  // Also drop a keyring-written bare "<app>" item that belongs to this name, so a
  // keyward remove of a visible secret actually removes it.
  if (auto c = readCredential(toWide(app_), name); c && c->username == name) {
    if (!CredDeleteW(toWide(app_).c_str(), CRED_TYPE_GENERIC, 0)) {
      const DWORD err = GetLastError();
      if (err != ERROR_NOT_FOUND)
        throw std::runtime_error("keyward: CredDeleteW failed for '" + name + "' (" +
                                 errorText(err) + ")");
    } else {
      removedAny = true;
    }
  }
  (void)removedAny;  // surgical & idempotent: a missing name is simply a no-op
}

std::vector<std::string> WindowsCredentialStore::list() {
  const std::string suffix = "@" + app_;
  const std::wstring filter = toWide("*" + suffix);  // "*@<app>"
  std::vector<std::string> names;

  DWORD count = 0;
  PCREDENTIALW* creds = nullptr;
  if (!CredEnumerateW(filter.c_str(), 0, &count, &creds)) {
    const DWORD err = GetLastError();
    if (err != ERROR_NOT_FOUND)  // no matching credentials is an empty store, not an error
      throw std::runtime_error("keyward: CredEnumerateW failed (" + errorText(err) + ")");
  } else {
    names.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
      const std::string target = fromWide(creds[i]->TargetName);
      // Strip the trailing "@<app>" to recover the caller's name. ends_with guards
      // against a target that merely contains "@<app>" mid-string.
      if (target.size() > suffix.size() &&
          target.compare(target.size() - suffix.size(), suffix.size(), suffix) == 0)
        names.push_back(target.substr(0, target.size() - suffix.size()));
    }
    CredFree(creds);
  }

  // A keyring-written newest-for-service secret sits at the bare "<app>" target;
  // its name is the UserName. Include it (deduped) so keyward enumerates it too.
  if (auto c = readCredential(toWide(app_), "list")) {
    if (!c->username.empty() && std::find(names.begin(), names.end(), c->username) == names.end())
      names.push_back(c->username);
  }
  return names;
}

}  // namespace keyward

#endif  // _WIN32
