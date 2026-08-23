// Interop oracle for keyward <-> Python `keyring` on Windows Credential Manager.
//
// This is the Windows counterpart of secret_service_interop_test.cpp, but the
// contract it pins is deliberately NARROWER, because the two backends are not
// byte-compatible the way they are on Linux:
//
//   - keyring's WinVaultKeyring stores the secret blob as **UTF-16-LE text**;
//   - keyward stores **raw bytes** (its Vault records are binary), and does NOT
//     re-encode them.
//
// So the interop that exists is a NAMESPACE alignment plus a *string* value
// contract: keyward writes where keyring looks (target "<name>@<app>", UserName
// "<name>"), and a value crosses intact exactly when it is UTF-16-LE. A plain
// keyward record (raw bytes) is therefore NOT a keyring-readable string, and a
// keyring password is only readable by keyward as its UTF-16-LE bytes. This test
// verifies both halves of that precise contract, so the limit is pinned, not
// merely documented. See docs/DESIGN.md.
//
// keyring is pinned in requirements-dev.txt and found by CMake at
// .venv/Scripts/keyring.exe; without it KEYWARD_KEYRING_CLI is undefined and this
// compiles to a single skip.
#include <gtest/gtest.h>

#if defined(_WIN32) && defined(KEYWARD_KEYRING_CLI)

#include <array>
#include <cstdio>
#include <string>
#include <utility>

#include "keyward/windows_credential_store.hpp"

using keyward::WindowsCredentialStore;

namespace {

// Both sides agree: keyring `service` == keyward `app`, keyring `username` ==
// keyward `name`. A throwaway service so a real app's credentials are never touched.
constexpr const char* kApp = "keyward-win-interop-test";

// UTF-16-LE encoding of an ASCII string: each byte followed by 0x00. keyring
// stores exactly this in the credential blob, so it is what keyward's raw get()
// must return for a keyring-written ASCII secret.
std::string utf16le(const std::string& ascii) {
  std::string out;
  out.reserve(ascii.size() * 2);
  for (char c : ascii) {
    out.push_back(c);
    out.push_back('\0');
  }
  return out;
}

// cmd.exe double-quoting is enough for our ASCII, space-free test identifiers.
std::string q(const std::string& s) { return "\"" + s + "\""; }

// Feed a password to `keyring set <app> <name>` via the child's stdin ("w" pipe),
// exactly as a user would type it. Returns the child exit status.
int keyringSet(const std::string& name, const std::string& password) {
  const std::string cmd =
      std::string(KEYWARD_KEYRING_CLI) + " set " + q(kApp) + " " + q(name) + " 2>nul";
  FILE* raw = _popen(cmd.c_str(), "w");
  if (raw == nullptr) return -1;
  const std::string line = password + "\n";  // getpass reads a line, strips the newline
  std::fwrite(line.data(), 1, line.size(), raw);
  return _pclose(raw);  // the child exit status
}

// Run `keyring get <app> <name>`, returning {exit status, stdout}.
std::pair<int, std::string> keyringGet(const std::string& name) {
  const std::string cmd = std::string(KEYWARD_KEYRING_CLI) + " get " + q(kApp) + " " + q(name);
  FILE* raw = _popen(cmd.c_str(), "r");
  if (raw == nullptr) return {-1, ""};
  std::string out;
  std::array<char, 256> buf{};
  while (std::fgets(buf.data(), static_cast<int>(buf.size()), raw) != nullptr) out += buf.data();
  return {_pclose(raw), out};
}

void keyringDel(const std::string& name) {
  const std::string cmd =
      std::string(KEYWARD_KEYRING_CLI) + " del " + q(kApp) + " " + q(name) + " 2>nul >nul";
  if (FILE* raw = _popen(cmd.c_str(), "r")) _pclose(raw);
}

std::string trimEol(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}

}  // namespace

// keyring writes a string; keyward SEES it (same namespace) and reads its bytes,
// which are the UTF-16-LE encoding of that string. This proves the namespace maps
// and pins the encoding boundary.
TEST(WindowsKeyringInterop, KeyringWriteIsReadableByKeywardAsUtf16le) {
  const std::string name = "kr-to-kw";
  const std::string secret = "s3cr3t-interop";
  keyringDel(name);
  ASSERT_EQ(keyringSet(name, secret), 0) << "keyring set failed";

  WindowsCredentialStore store{kApp};
  auto got = store.get(name);
  ASSERT_TRUE(got.has_value()) << "keyward could not see the keyring-written item";
  EXPECT_EQ(*got, utf16le(secret))
      << "keyward reads keyring's blob as raw bytes; they must be UTF-16-LE of the secret";

  store.remove(name);
  EXPECT_FALSE(store.get(name).has_value()) << "keyward remove should drop the keyring item too";
  keyringDel(name);  // belt-and-braces
}

// keyward writes UTF-16-LE bytes; keyring reads them back as the string. This is
// how a keyward caller stores a keyring-compatible *string* secret.
TEST(WindowsKeyringInterop, KeywardWriteOfUtf16leIsReadableByKeyring) {
  const std::string name = "kw-to-kr";
  const std::string secret = "hello-keyring";
  keyringDel(name);

  WindowsCredentialStore store{kApp};
  store.set(name, utf16le(secret));

  auto [rc, out] = keyringGet(name);
  EXPECT_EQ(rc, 0) << "keyring get failed on a keyward-written item";
  EXPECT_EQ(trimEol(out), secret)
      << "keyring did not decode keyward's UTF-16-LE blob as the string";

  store.remove(name);
  keyringDel(name);
}

// The documented LIMIT, pinned: a raw (non-UTF-16-LE) keyward value is NOT a
// keyring-readable string. keyward stores its binary Vault records this way, so
// keyring cannot decode them — mutual discovery, not mutual value-decoding.
TEST(WindowsKeyringInterop, RawKeywardValueIsNotAKeyringString) {
  const std::string name = "kw-raw";
  const std::string raw = "s3cr3t";  // plain ASCII bytes, NOT UTF-16-LE
  keyringDel(name);

  WindowsCredentialStore store{kApp};
  store.set(name, raw);

  auto [rc, out] = keyringGet(name);
  // keyring decodes the blob as UTF-16-LE; "s3cr3t" (6 bytes) is not the UTF-16-LE
  // of "s3cr3t" (which would be 12 bytes), so what keyring returns is NOT the value.
  EXPECT_NE(trimEol(out), raw)
      << "raw keyward bytes must not round-trip as a keyring string (that is the documented limit)";

  store.remove(name);
  keyringDel(name);
}

#else  // not Windows, or no keyring CLI

TEST(WindowsKeyringInterop, SkippedWithoutWindowsOrKeyring) {
  GTEST_SKIP() << "Windows keyring interop needs _WIN32 and the pinned keyring "
                  "(.venv/Scripts/pip install -r requirements-dev.txt)";
}

#endif
