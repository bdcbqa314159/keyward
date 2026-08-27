# keyward — security assessment & audit packet

A self-assessment to make an **independent security audit** cheap and effective:
what keyward is, what to review, what's already covered, and how to build and
reproduce it. keyward has **not** been independently audited; this document is the
starting point for one.

For the full threat model see [THREAT_MODEL.md](THREAT_MODEL.md); for the
architecture see [DESIGN.md](DESIGN.md).

## 1. What keyward is (one paragraph)

A cross-platform C++20 credential SDK: a thin facade over the OS credential vault
(macOS Keychain, Windows Credential Manager, Linux Secret Service) with an
encrypted-file fallback, a typed schema-driven record API, pluggable prompters
(CLI/TUI), and an access-gate authenticator (passphrase / biometric / fallback).
At-rest security is delegated to the audited OS stores; keyward owns the
integration, the schema, in-process handling, and the encrypted-file crypto.

## 2. Trust bars (what the audit is for)

- **Bar A — a user's own keys on their own machine.** keyward targets this today.
- **Bar B — others' high-value secrets / shared machines / catastrophic-if-breached.**
  Requires this audit + the agent + a 1.0 freeze. This packet exists to reach Bar B.

## 3. Attack surface — what to review (in priority order)

1. **Crypto composition** (`crypto_primitives.*`, `secret_box.*`): Argon2id KDF,
   XChaCha20-Poly1305 AEAD, **nonce management** (uniqueness per key), key sizes,
   the seal/unseal blob format. Primitives are Monocypher/libsodium (already
   audited) — review the *usage*, not the math.
2. **Key lifecycle & secure memory** (`secret.*`, `secure_memory.*`,
   `key_provider.*`): derive-once/cache, `Secret` (sodium_malloc, mlock, guard
   pages, zeroize), the documented **instant-of-use plaintext residual**.
3. **Untrusted-input parsers** (`record_codec.*`, `secret_box.*` unseal,
   `encrypted_file_format.*`): bounds/length handling on attacker-controlled
   bytes. Fuzzed in CI (see §4) — review the logic and the fail-closed paths.
4. **Encrypted file store** (`file_secret_store.*`): per-entry seal, keyless
   list/remove, legacy-plaintext migration, atomic durable writes + permissions
   (0600 / 0700 / Windows DACL), fail-closed on wrong passphrase/tamper.
5. **Platform backends** (`keychain_*`, `windows_credential_*`,
   `secret_service_*`): correct OS-API usage — Keychain accessibility class
   (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; device-bound, never
   iCloud-synced — note this is an accessibility protection class, *not* a
   per-item `SecAccessControl`/ACL), CredMan flags, libsecret attributes/locking,
   the Windows-CredMan-only fail-closed decision.
6. **The agent** (when built — see [AGENT_SCOPE.md](AGENT_SCOPE.md)): the IPC /
   socket / caller-trust boundary. This is the one *new* attack surface keyward
   introduces and the highest-value review target; it is not yet implemented.

## 4. What is already covered (so the audit can skip it)

- **Fuzzing** in CI: `decode_fields` and `unseal` (libFuzzer; `unseal` uses a
  token KDF cost in fuzz-only builds — production is byte-identical).
- **Sanitizers** in CI: ASan + UBSan + LSan on the full suite (Linux).
- **CI breadth**: 3-OS matrix (macOS/Ubuntu/Windows) + 3 Linux distros
  (arch/debian/fedora) + install-&-consume (`find_package`/pkg-config). ~126 tests.
- **Memory-protection verification**: tests assert guard pages / no-swap / no-core-dump
  are actually active (libsodium features force-enabled — see CMake).
- **One internal adversarial review already run** (independent third-party agent,
  read-only, per [ADVERSARIAL_REVIEW.md](ADVERSARIAL_REVIEW.md); report at
  [ADVERSARIAL_REVIEW_FINDINGS.md](ADVERSARIAL_REVIEW_FINDINGS.md)). It confirmed
  the crypto composition sound (nonce uniqueness, parser memory-safety,
  constant-time compare, backend error-laundering, atomic writes + permissions).
  All seven findings — F1 (High, format-downgrade) through F7 — are **fixed**,
  each confirmed one with a regression test. A **second, fresh** independent
  review of the fixed tree is the recommended next pre-audit step.

## 5. Known limitations / accepted residuals

- **Instant-of-use plaintext** for bearer secrets is irreducible in-process (the
  secret must be plaintext at the OS-API call and where the app uses it);
  minimized via secure memory + wipe, documented in THREAT_MODEL.
- **Windows Credential Manager has no per-app isolation** — any same-user process
  can `CredRead`. Namespacing is organizational, not a boundary.
- **Not independently audited** (this packet's purpose).

## 6. Build & reproduce

```sh
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
cmake --preset asan  && cmake --build --preset asan  && ctest --preset asan
```
Fuzzers (needs Homebrew LLVM — Apple clang lacks the libFuzzer runtime):
```sh
cmake -S . -B build/fuzz -DKEYWARD_BUILD_FUZZERS=ON -DKEYWARD_BUILD_TESTS=OFF -DKEYWARD_BUILD_TUI=OFF \
  -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
cmake --build build/fuzz && ./build/fuzz/fuzz_decode_fields -max_total_time=60
```

## 7. Dependencies (pinned — supply chain)

| Dep | Role | Pin |
|---|---|---|
| Monocypher | Argon2id + XChaCha20-Poly1305 | vendored, `third_party/monocypher/` |
| libsodium | secure memory, CSPRNG, constant-time | robinlinden/libsodium-cmake @ pinned commit (submodule pins libsodium) |
| FTXUI | optional TUI prompter | v5.0.0 (FetchContent) |
| GoogleTest | tests | v1.15.2 (FetchContent) |

## 8. Suggested audit scope

- **Scoped (~$5–20k):** items §3.1–3.3 + §3.6 (crypto composition, key lifecycle,
  parsers, and the agent IPC when it exists) — the risky core.
- **Full (~$20–80k):** all of §3 including the platform backends.

## 9. Vendors & funding

C/C++-native, credential/crypto track record (verify publicly):
- **X41 D-Sec** — GnuPG, Git, NSS (all C). Closest analog; top pick.
- **Trail of Bits** — curl; deep C++ memory-safety + fuzzing.
- **Quarkslab** — low-level C/C++ + crypto.
- (Cure53 — strong on crypto-protocol/design; lighter on deep C++ memory.)

Funding (audit is sequenced on adoption, not budget): **OSTIF** (organized the
curl/Git audits, pairs projects with X41/ToB), **OTF** Red-Team Lab,
**Sovereign Tech Agency**, GitHub Secure Open Source Fund.

## 10. Out of scope for the audit

The security of the OS keychains themselves (Apple/Microsoft/GNOME — keyward's
trust anchor); the audited crypto primitives' internals; root/kernel/hypervisor/
physical attackers; a compromised process already holding a decrypted secret.
