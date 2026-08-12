# Gap 3 — the Windows Credential Manager backend

## Context
keyward is consumable on macOS (real Keychain in front, `0600` file fallback). On **Windows** it
currently falls all the way through to the plaintext `0600` file — and on Windows that `0600` is
just the read-only *attribute*, not a real ACL, so it's barely protected. A lot of customers are on
Windows, so this is the load-bearing gap: give Windows its **native OS vault**.

The native vault is **Windows Credential Manager** (a.k.a. Credential Locker), reached through the
Win32 Credential Management API. It's the structural twin of the macOS Keychain: `CredWrite` /
`CredRead` / `CredDelete` ↔ `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`. It's DPAPI-backed,
so **the OS encrypts at rest with a key bound to the user's logon** — we don't roll crypto. **This
backend body is yours to write** — the Win32 calls are the learning. I've laid down the skeleton,
the build wiring, and a failing contract test.

## Background — how Credential Manager stores a generic credential
A "generic credential" is a named blob owned by the current user:
- **Target name** — the key. A wide (`LPWSTR`, UTF-16) string. We namespace it per app so two apps'
  secrets can't collide: `keyward:<app>:<name>`.
- **Credential blob** — the value. A **counted byte buffer** (`CredentialBlob` + `CredentialBlobSize`),
  *not* a C string. It can contain embedded NULs → always use the size, never `strlen`.
- **Type** `CRED_TYPE_GENERIC`, **persistence** `CRED_PERSIST_LOCAL_MACHINE` (this machine, this user).

The three calls:
- `CredWriteW(&CREDENTIALW, 0)` — upsert (write replaces an existing target).
- `CredReadW(targetName, CRED_TYPE_GENERIC, 0, &PCREDENTIALW)` — on success you own the returned
  struct; copy the blob out, then `CredFree` it. On miss it returns `FALSE` and `GetLastError()` is
  `ERROR_NOT_FOUND`.
- `CredDeleteW(targetName, CRED_TYPE_GENERIC, 0)` — `ERROR_NOT_FOUND` on a missing item is fine.

### The one Windows wrinkle: UTF-16
The API is wide-char. Our `SecretStore` surface is UTF-8 `std::string`. So the target name must be
converted UTF-8 → UTF-16 for the calls (`MultiByteToWideChar`). The **blob stays raw bytes** — no
conversion, no encoding assumptions (it may be arbitrary sealed bytes later).

## The flaw you're removing
`defaultSecretStore` (`src/default_store.cpp`) only wraps a native vault `#if defined(__APPLE__)`;
the `#else` branch has a literal `// TODO: Windows Credential Manager ... in front here` and returns
the plaintext file store. You're filling that in for Windows.

## Your task
Implement the body of `src/windows_credential_store.cpp` (declared in
`include/keyward/windows_credential_store.hpp`) so `WindowsCredentialStore` satisfies the contract
test. Public surface (mirrors `KeychainSecretStore`; change it if you'd shape it differently and
I'll re-pin the test):

```cpp
explicit WindowsCredentialStore(std::string app = "keyward");
std::optional<std::string> get(const std::string& name) override;
void set(const std::string& name, const std::string& value) override;
void remove(const std::string& name) override;
std::string location() const override;   // e.g. "Windows Credential Manager (app=...)"
```

Rules that are part of the contract:
- **Round-trip fidelity.** `set` then `get` returns the exact bytes, including embedded NULs.
- **Upsert.** A second `set` on the same name overwrites; it does not error or duplicate.
- **Surgical remove.** `remove` deletes only that name; a missing name is a no-op (not an error).
- **Fail closed on oversize.** Credential Manager caps the blob at
  `CRED_MAX_CREDENTIAL_BLOB_SIZE` (2560 bytes). If `value` exceeds it, **throw** — never silently
  truncate, and never fall back to the plaintext file. (No chunking; that's YAGNI until a real
  payload needs it.)
- **No secret in any error.** Exception messages carry the name/size, never the value.

## Acceptance (the oracle)
`tests/windows_credential_store_test.cpp` (target `windows_credential_store_tests`), built and run on
Windows. Green = done:
```
cmake --build build/debug --config Debug
ctest --test-dir build/debug -C Debug -R WindowsCredentialStore --output-on-failure
```
On non-Windows the test compiles to a single `GTEST_SKIP` so the suite stays green cross-platform.
The test uses a throwaway app namespace (`keyward-test-<...>`) and cleans up after itself, so it
won't pollute your real Credential Manager.

## Hints & research (pointers, not answers)
- L1: read `src/keychain_secret_store.cpp` — the same three-method shape (query → copy out → free),
  just a different OS API. Mirror its structure.
- L1: docs — `CredWriteW`, `CredReadW`, `CredDeleteW`, `CREDENTIALW`, `CredFree` on learn.microsoft.com.
- L2 (UTF-16): `MultiByteToWideChar(CP_UTF8, 0, s, -1, ...)` — call once with `cchWideChar = 0` to
  get the length, size a `std::wstring`, call again to fill. Same pattern in reverse if you ever need
  it. Watch the NUL-termination for the *target name* (it's a string) vs the *blob* (counted bytes).
- L2 (lifetime): `CredReadW` allocates; you must `CredFree` the returned pointer on **every** exit
  path after a successful read (RAII or a careful single free).
- L3 ("show me"): ask and I'll show a minimal `CredWrite`/`CredRead` pair and we move on.

## Constraints
- C++20, `#if defined(_WIN32)` guards; the file compiles empty elsewhere (like the Keychain one).
- No new dependency — `Advapi32` is a system lib, already wired in CMake under `if(WIN32)`.
- Value semantics; no secret in logs/errors/`operator<<`.

## Stretch
- Wire `WindowsCredentialStore` into `defaultSecretStore`'s `#if defined(_WIN32)` branch (in front of
  the file store via `FallbackSecretStore`, mirroring macOS) so `Vault` uses it automatically.
- A host-gated smoke test that goes through `Vault::save/load<T>` on a real struct.

## My working notes
<!-- scratchpad — yours -->
