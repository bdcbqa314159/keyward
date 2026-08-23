# keyward — adversarial security review findings

Read-only internal review per `docs/ADVERSARIAL_REVIEW.md`. Disposition: assume
broken, prove it. Scope: the whole SDK core (crypto composition, key lifecycle,
parsers, file store, platform backends, authenticator layer). Attacker models:
(A) can read/restore stored files (backup, sync folder, disk image); (B) a
same-uid process (mostly out of scope per THREAT_MODEL); (C) can feed crafted
bytes to any parser.

Bottom line: the crypto composition is sound — **no nonce-reuse (empirically
confirmed), no parser memory-safety bug, no fail-open in the AEAD path**, and the
at-rest permissions (0600/0700) hold. The real weaknesses are all *above* the
crypto, in the **file store's format layer**, where the encrypted-vs-plaintext
decision is made from unauthenticated bytes: an attacker with one file write
bypasses AEAD entirely and can inject, launder, enumerate, and destroy
credentials (F1), and the plaintext tier silently corrupts binary records (F2).
Findings ranked below; all High/Medium items are confirmed by runtime PoC
against real libsodium + Monocypher, and a reinforcement pass hardened the
"resisted attack" claims and added F6–F7.

**Findings at a glance:** F1 plaintext-injection/downgrade (**High**, confirmed);
F2 binary-unsafe plaintext tier (**Medium**, confirmed); F3 derivation buffers
swappable (Low); F4 `KEYWARD_PASSPHRASE` residual (Low/Info); F5 unchecked salt
length (Info); F6 derive-once cache assumes fixed salt (Low); F7 length-field
truncation (Info).

---

## F1 — Encrypted file store accepts unauthenticated plaintext injection (format downgrade)

- **Severity:** High (integrity bypass) · **Confidence:** CONFIRMED (runtime PoC, real Monocypher AEAD)
- **Location:** `src/file_secret_store.cpp:248-253` (`get`), same pattern in
  `set`/`remove`/`list`; enabled by `encrypted_file_format.cpp:95-98`
  (`is_encrypted_file`).

**What.** In encrypted mode, `get()` decides the file's format at runtime by
sniffing the magic line:

```cpp
if (!is_encrypted_file(text)) return plaintextGet(path_, name);  // legacy, not yet migrated
```

Nothing binds a store to "is encrypted." The mode is a runtime property of the
*caller* (did it pass a KeyProvider), not of the *file*. So an attacker who can
**write** the store file (model A — a sync folder and a restorable backup are
both read-write) replaces the encrypted file with a plaintext one:

```
token=attacker-controlled-value
```

The next `get("token")` sees no magic line, takes the "legacy plaintext" branch,
and returns `attacker-controlled-value` — **no passphrase, no AEAD check.** The
application consumes an attacker-chosen credential as authentic.

**Why it matters.** THREAT_MODEL.md claims AEAD authentication "reject[s]
tampered, truncated, or foreign blobs instead of mis-parsing them," and
SECURITY_ASSESSMENT §3.4 lists "fail-closed on wrong passphrase/tamper" as
covered. This is a tamper that is *accepted*. The existing
`TamperedEntryThrows` test (`file_store_encryption_test.cpp:100`) only flips a
byte *inside* an encrypted entry — AEAD catches that. It never tests stripping
the magic line, which is the cheaper attack.

**Repro (executed — real Monocypher crypto, real file-store code; only the
libsodium wrapper was replaced with a functional malloc/memset/arc4random stub,
which none of these paths depend on for behaviour):**
1. `FileSecretStore store{path, provider("pw")}; store.set("token","REAL");`
   — on-disk file confirmed to start with `keyward-file-v1` and to be real
   AEAD-sealed.
2. Overwrite `path` with the single ASCII line `token=EVIL-INJECTED\n` (no
   magic line).
3. `FileSecretStore reopened{path, provider("pw")}; reopened.get("token")`
   → returned `"EVIL-INJECTED"`, and the passphrase provider was **never
   invoked** (instrumented). AEAD bypassed entirely.

**Escalation — CONFIRMED: injected plaintext is laundered into an authentic
encrypted entry.** After step 2, a victim's next *ordinary* write —
`store.set("unrelated","x")` — takes the migration branch
(`file_secret_store.cpp:295-305`), which re-seals every "legacy" entry under the
**real** key. The attacker's `token=EVIL-INJECTED` and `api_key=EVIL2` are now
stored as genuine XChaCha20-Poly1305 entries; the plaintext is scrubbed from
disk; `is_encrypted_file` is true again. `get("token")` returns `EVIL-INJECTED`
from an entry that *passes* AEAD verification and is byte-indistinguishable from
one the user set. **One-time write access → permanent credential substitution
that survives every subsequent passphrase entry and integrity check.** This is
the reason the severity is High rather than Medium.

**Related non-fail-closed behaviour (also executed).** Corrupting a single byte
of the magic line (not a full replacement) makes `get()` fall to the legacy
path and return the **base64 ciphertext body as the credential value** (e.g.
`HY7PHux39X9k…`) rather than throwing. So a merely *corrupted* — not
attacker-crafted — encrypted header is not rejected either; it yields garbage.
The fail-closed guarantee for "tampered/truncated encrypted file" does not hold
for anything that touches the header line.

**Breadth — the downgrade poisons every operation, not just `get()`
(reinforcement pass, executed).** With the same plaintext file dropped in:
- `list()` returns the **attacker-chosen names** verbatim (confirmed: a planted
  `injected=ZZZ` file made `list()` return `["injected"]`) — the store's
  enumeration is now attacker-controlled.
- `remove()` on the downgraded file takes the plaintext-rewrite branch
  (`file_secret_store.cpp:333-337`) and **rewrites the whole store as a plaintext
  file** (confirmed: `is_encrypted_file` is false afterward), permanently
  discarding the original AEAD-sealed entries. So a single injected write plus
  any later `remove()` is also a **destructive / availability** attack on the
  real credentials, not only an integrity one.

**Fix direction.** When a KeyProvider is configured, a file that is present and
non-empty but *not* `is_encrypted_file` must be treated as an error (fail
closed), not silently trusted as legacy. Migration from a genuine pre-encryption
plaintext file should be an explicit, one-time opt-in (e.g. a `migrate()` call or
a construction flag), not the default silent behaviour on every read. There is
no way to make the plaintext-vs-encrypted decision safely from unauthenticated
file bytes alone, so the safe default must be "refuse."

---

## F2 — Plaintext file store is not binary-safe: silently corrupts/loses Vault records

- **Severity:** Medium (data loss / availability; corruption of credentials) · **Confidence:** CONFIRMED (runtime PoC)
- **Location:** `src/file_secret_store.cpp:86-96` (`readAll` + `trimTrailing`),
  `:100-109` (`serialize`), `:273-285` (`set` plaintext branch).

**What.** The plaintext tier stores values as raw bytes on `NAME=value\n` lines
and reads them back with `std::getline` + `trimTrailing`. But `Vault` stores
`encode_fields()` output — length-prefixed **binary** that routinely contains
`0x0a` (any field name/value of length 10 encodes a length byte `0x0a`; a value
may itself contain a newline) and may end in a byte that `trimTrailing` strips
(`\r`, `\n`, space, tab).

- An embedded `0x0a` truncates the value at read (`getline` splits on `\n`).
- A trailing whitespace byte is silently removed by `trimTrailing`
  (`:78-83`).

Either way `decode_fields` later fails and `Vault::load` returns `nullopt` — the
credential is gone. The encrypted format base64-encodes values *precisely* to
survive a line-based file (`encrypted_file_format.hpp:19-20`); the plaintext
path never got the same treatment.

**Why it matters.** The plaintext file store is the **sole** tier on Linux
without libsecret and on BSD (`default_store.cpp:107-113`), and it is what a bare
`Vault("app")` uses there. So on those platforms a perfectly ordinary credential
can be unrecoverable after a save/load round-trip, with no error at write time.

**Repro (executed).** `FileSecretStore s{path};` (plaintext mode):
- `s.set("k", "a\nb")` (3 bytes, embedded `0x0a`) → `s.get("k")` returned
  `"a"` (1 byte) — value truncated at the newline.
- `s.set("k2", "secret ")` (trailing space) → `s.get("k2")` returned
  `"secret"` — trailing byte stripped by `trimTrailing`.

On a no-libsecret host this is what `Vault("app")` writes through, since the
serialized blob routinely contains `0x0a`. `FileEncryption.EmptyValueRoundTrips`
and the vault tests use an in-memory or encrypted store, so this path is
untested in CI.

**Fix direction.** Make the plaintext writer/reader binary-safe the same way the
encrypted format is — base64 (or hex) the value — or drop the plaintext tier's
ability to hold `Vault` blobs entirely and require encryption where the file is
the sole store. Do not rely on `trimTrailing`, which is lossy for binary.

---

## F3 — Argon2 work buffer and transient passphrases are swappable / core-dumpable

- **Severity:** Low · **Confidence:** High (behaviour); Medium (impact)
- **Location:** `src/secret_box.cpp:48` (`std::vector<uint8_t> work` — 100 MB),
  `src/passphrase_authenticator.cpp:26` (`work`, 8 MB) and `:28` (`hash`),
  `src/key_provider.cpp:15-18` (the passphrase `std::string`).

**What.** THREAT_MODEL.md states the derived key runs on libsodium secure memory
"guard-paged, `mlock`ed (never swapped)." That is true of the *output* `Secret`.
It is **not** true of the Argon2 *work area*, which is a plain heap `std::vector`
holding password-derived memory-hard state during the ~2.2 s derivation, nor of
the transient passphrase copies, which are plain `std::string`s. All are
`crypto_wipe`/`secure_zero`'d at end of use, but during use they are pageable and
included in a core dump. If the process is paged out or dumps mid-derivation,
password-derived material (and, in `key_provider`, the passphrase itself) reaches
disk — exactly the swap/core-dump exposure the secure allocator exists to
prevent.

**Why it matters.** It's a narrower window than a persisted key, and capturing it
needs disk/swap access (model A) plus timing, so impact is limited. But it
contradicts a stated hardening guarantee, and the fix is cheap for the passphrase
copies.

**Fix direction.** Hold the transient passphrase in a `Secret`/secure buffer
through `derive_key` and the verifier. The 100 MB Argon2 work area is harder
(secure allocation of that size is impractical); at minimum document it as a
residual so the "never swapped" claim is scoped to the key, not to derivation
state.

---

## F4 — `KEYWARD_PASSPHRASE` lives in the environment and in an unwiped copy

- **Severity:** Low / Info (largely out of scope: same-uid) · **Confidence:** High
- **Location:** `src/default_store.cpp:27-33`.

**What.** The headless on-ramp reads the passphrase from an env var and copies it
into a `std::string` captured by the KeyProvider lambda — never wiped, and the
original stays in `environ` (readable via `/proc/self/environ`, `ps e`,
inherited by children) for the process lifetime.

**Why it matters.** This is inherent to env-var secrets and the mechanism is
opt-in and documented. Same-uid exposure is explicitly out of scope per
THREAT_MODEL. Flagged for completeness because it interacts with F3 (the copy is
also swappable).

**Fix direction.** Document the env-var residual next to the on-ramp; optionally
unset it after first read. Prefer a file-descriptor / prompt source for anything
above Bar A.

---

## F5 — `derive_key` does not validate salt length (defense-in-depth / fragility)

- **Severity:** Info · **Confidence:** High (no-crash CONFIRMED by runtime PoC)
- **Location:** `src/secret_box.cpp:43-57`, salt sourced from the parsed file at
  `file_secret_store.cpp:261` / `secret_box.cpp:100`.

**What.** The salt fed to Argon2 in the file-store path comes from the
unauthenticated file header and its length is passed through unchecked
(`static_cast<uint32_t>(salt.size())`). In the vendored Monocypher this is
**not** currently exploitable — `crypto_argon2` has no salt-size assertion, so a
zero/short salt neither crashes nor reads out of bounds (verified statically at
`third_party/monocypher/monocypher.c:768-769`, and confirmed at runtime: a
crafted `salt=` (empty) file threw a clean `cannot decrypt` error, no abort/UB).
But the `kSaltSize` "16 bytes
recommended" contract is unenforced, so a future primitive swap or a Monocypher
update that adds the standard `salt_size >= 8` assertion would turn a crafted
file (empty `salt=`) into a crash (DoS, model C). Wrong salt already fails closed
via AEAD, so there is no confidentiality impact today.

**Fix direction.** Reject a parsed salt whose length isn't `kSaltSize` before
calling `derive_key`, consistent with the fail-closed posture elsewhere.

---

## F6 — Derive-once key cache assumes the file's salt never changes

- **Severity:** Low (robustness / latent corruption) · **Confidence:** CONFIRMED (reinforcement PoC)
- **Location:** `src/file_secret_store.cpp:229-237` (`ensureKey`), used by
  `get` (`:261`) and `set` (`:294`).

**What.** `ensureKey` derives the key on first use and caches it for the store's
lifetime, keyed to the salt seen *then*. It never re-derives if the file's salt
later differs. Two consequences, both surfaced in the reinforcement pass:

- **Confidentiality-safe but availability-fragile:** if the file is replaced with
  one carrying a different salt, `get()` fails closed (the cached key fails AEAD
  — confirmed, it throws). Good for security, but it also means a *legitimate*
  salt rotation or a second store instance sharing the path becomes unreadable
  without reconstructing the object.
- **Latent corruption on write:** in the "existing encrypted file" branch, `set`
  calls `ensureKey(ef.salt)` to "keep the file's existing salt so the cached key
  stays valid" — but if a key was already cached under a *different* salt,
  `ensureKey` does nothing, and `set` then seals the new entry under the stale
  key while writing the *file's* (different) salt into the header. The result is
  an internally inconsistent file: some entries decrypt, the newly written one
  does not.

**Why it matters.** Not exploitable for disclosure (everything fails closed), but
it's a data-integrity footgun for any flow where a `FileSecretStore` outlives a
salt change or two instances touch the same path.

**Fix direction.** Bind the cached key to the salt it was derived from and
re-derive (or hard-error) when the on-disk salt differs, rather than silently
reusing a key for a salt it doesn't match.

---

## F7 — `encode_fields` length prefixes truncate `size_t` to `uint32_t`

- **Severity:** Info · **Confidence:** High
- **Location:** `src/record_codec.cpp:9-14,32-36` (`put_u32(out, f.name.size())`
  / `put_u32(out, f.value.size())`).

**What.** Field name/value lengths are written with a narrowing
`size_t → uint32_t` conversion and no guard. A field ≥ 4 GiB would write a
truncated length, and `decode_fields` would then desync (read the wrong number
of bytes) — a parse corruption, not a memory-safety bug (`decode_fields`'
bounds checks still hold). Not reachable with real credentials (OS backends cap
blob sizes far below this — Windows at 2560 bytes), so it is purely
defense-in-depth.

**Fix direction.** Reject a field whose size exceeds `UINT32_MAX` in
`encode_fields` rather than silently truncating.

---

## What resisted attack (checked, found sound)

- **Nonce uniqueness — the #1 target. (Empirically confirmed.)** XChaCha20's
  24-byte nonce is drawn fresh per entry from the libsodium CSPRNG on every `set`
  and every migrated entry (`file_secret_store.cpp:301,307`; `secret_box.cpp:90-91`).
  No counter, no derived nonce, no reuse across the shared file key. `remove`
  preserves existing ciphertext rather than re-sealing, so it introduces no reuse
  either. **Reinforcement PoC:** 100 seal operations (50 creates + 50 updates
  under one cached key) produced **100 distinct on-disk nonces** — a `(key,nonce)`
  collision would have forced fewer; and an entry *update* was verified to draw a
  fresh nonce rather than reuse the prior one. The 96-bit random-nonce collision
  bound is not a concern at credential scale.
- **`decode_fields` / `record_codec`.** Length arithmetic is done as
  `blob.size() - i < len` with `i` provably `<= blob.size()` at each step; no
  `i + len` addition that could overflow, no OOB read. Version-byte gate up
  front. Fuzzed in CI. I could not find a crashing or over-read input.
- **`unseal` / `aead_open`.** Short-input guards (`< kMacSize`, `< kPrefix +
  kMacSize`) are correct; a bad key/nonce/tag returns `nullopt`, never a
  partial-accept. AEAD tag is 128-bit; forgery is infeasible.
- **base64 decoder.** Strict (length %4, padding only at end, alphabet checked),
  fails closed on garbage, no OOB.
- **Constant-time comparison.** `Secret::equals` and `verify_passphrase` both go
  through `sodium_memcmp`; verifier is salt‖Argon2id and reveals nothing.
- **Authenticator Unavailable-vs-Denied contract.** Biometric (macOS/Windows),
  polkit, and passphrase all map "could not ask" → `Unavailable` and a real "no"
  → `Denied`/`Cancelled`; `FallbackAuthenticator` only falls through on
  `Unavailable`. A denied biometric does **not** fall through to passphrase.
  `Vault::ensure` fails closed on a present-but-denied secret rather than
  prompting.
- **Platform backends' error laundering.** Keychain, Secret Service, and
  CredMan all distinguish a genuine miss from an error and throw on the latter;
  the locked-keyring fail-closed logic (unlock-or-throw, verify-on-remove) is
  present and correct. Windows is CredMan-only (no silent file downgrade).
- **Atomic writes + at-rest permissions. (Permissions empirically confirmed.)**
  temp-file + `fsync` + `rename` (POSIX) / `MoveFileEx` (Windows), owner-only from
  creation, dir fsync for the rename. Reinforcement PoC on the real writer:
  credentials file lands at **mode 0600** and its directory at **0700**.
- **Cached-key consistency under a swapped file. (Reinforcement, executed.)**
  If the store file is replaced underneath a live `FileSecretStore` with one
  whose salt differs from the cached key's, `get()` **fails closed (throws)**
  rather than returning wrong plaintext — the stale key simply fails AEAD. (Note
  the flip side is a robustness footgun, F6 below: it can also make a *legitimate*
  salt change mid-lifetime unreadable, and can produce an internally
  inconsistent file if `set` runs against a swapped salt with a key already
  cached.)

---

## Build / verification method

libsodium 1.0.22 and GoogleTest were installed (Homebrew). The project's CMake
pulls both via `FetchContent` (network), so instead of that path the real
sources were compiled directly against **system libsodium** and the vendored
Monocypher (real Argon2id + XChaCha20-Poly1305) — i.e. the shipping crypto and
all file-store/format/authenticator logic, no substitutions.

- **F1, F2, F5 — confirmed by standalone PoC against real libsodium** (the
  earlier stubbed-wrapper run reproduced identically, so the results do not
  depend on the allocator). PoC sources in the session scratchpad.
- **Reinforcement pass (executed against the real code).** Nonce uniqueness —
  100 seals → 100 distinct nonces, updates re-nonce (R1/R2); at-rest permissions
  0600 file / 0700 dir (R3); F1 breadth — downgrade poisons `list()` and
  `remove()` too (R4); cached-key vs swapped-salt fails closed (R5, → F6). These
  drove the empirical confirmations in "What resisted attack" and findings F6/F7.
- **Regression / "resisted attack" validation — full suites run and GREEN**
  against real libsodium (macOS host): `record_codec` (10), `secret_box` (6),
  `crypto_primitives` (9), `encrypted_file_format` (10), `file_store_encryption`
  (7), `passphrase_authenticator` (7), `key_provider` (4), `authenticator` (6),
  `fallback_authenticator` (5), `default_store` (4), `secret` (4), `secret_eq`
  (4), `secure_string` (3, +1 skip — heap-quarantine artifact, not a defect),
  `vault` (7), `schema` (5), `prompter` (6), `conformance` (9). **The suite is
  green yet contains no case for F1 or F2 — the coverage gap is real, not
  theoretical.**

## What I could NOT verify / did not attack

- **Runtime memory protections (F3).** `secure_memory_protection_test` is
  Linux-only (it parses `/proc/self/smaps`) and compiles to a `GTEST_SKIP` on
  this macOS host, so guard-page / no-swap / no-core-dump could not be asserted
  here. Note this test would not cover F3 regardless: F3 concerns the Argon2
  work buffer and transient passphrase, which deliberately do **not** go through
  `secure_alloc`. F3 remains static/definitional.
- **Fuzzers.** `decode_fields` / `unseal` libFuzzer harnesses need a Clang with
  the libFuzzer runtime (Homebrew LLVM); not run here. Both parsers have passing
  unit suites and were traced by hand; CI runs the fuzzers.
- **Concurrent-writer lost updates.** Documented as an accepted residual
  (advisory locking absent); I did not attempt to race two writers.
- **The vendored primitives themselves** (Monocypher, libsodium) — out of scope
  by the runbook; I only checked keyward's *usage* and the one salt-assertion
  behaviour relevant to F5.
- **The agent daemon** — not implemented, out of scope.
- **TUI prompter (FTXUI) internals** — read the contract, not the FTXUI-backed
  implementation's terminal-state handling.
- **Real OS-backend behaviour** (actual Keychain ACLs, live D-Bus locking,
  CredMan quirks) — reasoned from the API calls, did not run against live
  services.

---

## Regression tests to add

Drop-in GoogleTest cases in the repo's existing style. F1/F2/F5 tests go in
`tests/file_store_encryption_test.cpp`, which already defines the `TempFile`,
`provider()` and `readRaw()` helpers used below (add a `writeRaw` helper — given
first). They are written to assert the **desired fail-closed / correct
behaviour**, so each is **RED against `main` today and turns GREEN once the
corresponding fix lands** — the "test that fails before the fix" the runbook
asks for. All were validated to fail against current code by the PoCs.

Shared helper to add near `readRaw` in that file:

```cpp
static void writeRaw(const fs::path& p, const std::string& s) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(s.data(), static_cast<std::streamsize>(s.size()));
}
```

### F1 — plaintext-format injection must fail closed

```cpp
// An encrypted store must NOT silently trust a plaintext-format file dropped in
// by someone with file-write access. Today get() returns the attacker's value
// with the passphrase never consulted; the fix must fail closed (throw) or at
// minimum never return unauthenticated bytes.
TEST(FileEncryption, RejectsPlaintextFormatWhenEncryptionConfigured) {
  TempFile tmp("inject");
  { FileSecretStore s{tmp.path, provider("pw")}; s.set("token", "REAL"); }
  ASSERT_TRUE(keyward::is_encrypted_file(readRaw(tmp.path)));  // sanity: really encrypted

  // Attacker (file-write) replaces it with a plaintext line, no magic header.
  writeRaw(tmp.path, "token=EVIL-INJECTED\n");

  FileSecretStore reopened{tmp.path, provider("pw")};
  // Desired: a configured-encrypted store treats a non-encrypted file as tamper.
  EXPECT_THROW(reopened.get("token"), std::runtime_error);
  // It must never hand back the injected bytes.
  // (If the chosen fix returns nullopt instead of throwing, swap the line above
  //  for: EXPECT_NE(reopened.get("token"), std::optional<std::string>("EVIL-INJECTED"));)
}
```

```cpp
// The injection must not survive being laundered into an authentic encrypted
// entry by the next legitimate write (migration re-seals "legacy" entries under
// the real key). Today the attacker value ends up AEAD-authenticated and
// indistinguishable from a real one.
TEST(FileEncryption, DoesNotLaunderInjectedPlaintextOnNextSet) {
  TempFile tmp("launder");
  { FileSecretStore s{tmp.path, provider("pw")}; s.set("token", "REAL"); }
  writeRaw(tmp.path, "token=EVIL-INJECTED\napi_key=EVIL2\n");

  FileSecretStore s{tmp.path, provider("pw")};
  // A normal write must not silently re-seal attacker-planted plaintext.
  // Whether the fix throws here or refuses to migrate, the injected values must
  // never become readable authentic entries.
  EXPECT_ANY_THROW(s.set("unrelated", "x"));
  FileSecretStore reopened{tmp.path, provider("pw")};
  EXPECT_NE(reopened.get("token"), std::optional<std::string>("EVIL-INJECTED"));
  EXPECT_NE(reopened.get("api_key"), std::optional<std::string>("EVIL2"));
}
```

```cpp
// A corrupted magic line (a bit-flip, not a full replacement) must fail closed,
// not fall through to the legacy path and return the base64 ciphertext body as
// the "value".
TEST(FileEncryption, CorruptMagicLineFailsClosed) {
  TempFile tmp("badmagic");
  { FileSecretStore s{tmp.path, provider("pw")}; s.set("token", "REAL"); }
  std::string raw = readRaw(tmp.path);
  raw[0] = 'X';  // "keyward-file-v1" -> "Xeyward-file-v1"
  writeRaw(tmp.path, raw);

  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_THROW(s.get("token"), std::runtime_error);
}
```

```cpp
// The downgrade must not poison the keyless operations either: list() must not
// surface attacker-chosen names, and remove() must not silently convert the
// store to plaintext and discard the real ciphertext.
TEST(FileEncryption, DowngradeDoesNotPoisonListOrRemove) {
  TempFile tmp("breadth");
  { FileSecretStore s{tmp.path, provider("pw")}; s.set("real", "R"); }
  writeRaw(tmp.path, "injected=ZZZ\n");

  FileSecretStore s{tmp.path, provider("pw")};
  // Desired: enumerating a tampered store is an error, not a list of planted names.
  EXPECT_THROW(s.list(), std::runtime_error);
  // Desired: remove() on a tampered store must not rewrite it as plaintext.
  EXPECT_THROW(s.remove("whatever"), std::runtime_error);
  // (If the fix chooses to no-op instead of throw, assert the file is not left in
  //  plaintext format:  EXPECT_TRUE(keyward::is_encrypted_file(readRaw(tmp.path)));)
}
```

> Note on migration: if a legitimate legacy-plaintext → encrypted upgrade path is
> kept, it should be a distinct, explicit opt-in (e.g. a `migrate()` call or a
> constructor flag), and the four tests above should use the *non*-migrating
> default. Add a separate positive test for that explicit path so migration
> stays supported without being the silent default.

### F6 — cached key must not be reused for a mismatched salt

```cpp
// A store's cached key is derived from the salt seen on first use. If the file's
// salt later differs, the store must not seal new entries under the stale key
// while writing the new salt into the header (which produces a file where some
// entries decrypt and some don't). Deriving-per-salt or hard-erroring both make
// this pass; today set() writes an internally inconsistent file.
TEST(FileEncryption, DoesNotSealUnderStaleKeyAfterSaltChange) {
  TempFile a("c-a"), b("c-b");
  { FileSecretStore s{b.path, provider("pw2")}; s.set("x", "1"); }  // file with a different salt
  const std::string other = readRaw(b.path);

  FileSecretStore s{a.path, provider("pw")};
  s.set("x", "1");                 // caches key for a.path's salt
  writeRaw(a.path, other);         // swap in b.path's file (salt differs)
  s.set("y", "2");                 // must not seal "y" under the stale key + b's salt

  // Reopen fresh (correct key for b's salt) and require internal consistency:
  // whatever set() persisted for "y" must be decryptable, or set() should have
  // refused. Today "y" is unreadable while "x" is fine.
  FileSecretStore reopened{a.path, provider("pw2")};
  EXPECT_NO_THROW({ auto v = reopened.get("y"); (void)v; });
}
```

### F2 — plaintext tier must be binary-safe (or refuse binary)

```cpp
// The plaintext store must round-trip arbitrary bytes, including 0x0a and
// trailing whitespace — Vault stores length-prefixed binary through it on
// platforms with no OS vault. Today getline truncates at 0x0a and trimTrailing
// eats trailing spaces.
TEST(FilePlaintext, RoundTripsBinaryValuesLosslessly) {
  TempFile tmp("bin");
  FileSecretStore s{tmp.path};  // plaintext mode (no provider)

  const std::string with_newline = "a\nb";     // embedded 0x0a
  const std::string with_trailing_ws = "secret ";
  const std::string with_nul = std::string("x\0y", 3);
  s.set("k1", with_newline);
  s.set("k2", with_trailing_ws);
  s.set("k3", with_nul);

  EXPECT_EQ(s.get("k1"), with_newline);
  EXPECT_EQ(s.get("k2"), with_trailing_ws);
  EXPECT_EQ(s.get("k3"), with_nul);
}
```

```cpp
// End-to-end: a Vault record whose serialized blob contains 0x0a must survive a
// save/load through the plaintext file tier. Self-contained record (DemoCred in
// vault_test.cpp is in an anonymous namespace and not reachable here). The
// embedded newline in `token` forces a 0x0a in the encode_fields body; ordinary
// length prefixes also routinely produce 0x0a bytes.
namespace {
struct BinCred {
  std::string user;
  std::string token;
  bool operator==(const BinCred&) const = default;
  static keyward::Schema<BinCred> schema() {
    return {{"user", &BinCred::user}, {"token", &BinCred::token, keyward::Sensitive}};
  }
};
}  // namespace

TEST(FilePlaintext, VaultRecordSurvivesPlaintextTier) {
  TempFile tmp("vaultbin");
  keyward::Vault v{std::make_unique<FileSecretStore>(tmp.path)};
  const BinCred in{"u", "tok\nen-value"};  // newline in a field value
  v.save("svc", in);
  const auto out = v.load<BinCred>("svc");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}
```
(Needs `#include "keyward/vault.hpp"` and `#include "keyward/schema.hpp"` at the
top of the test file.)

### F5 — reject a malformed salt length before deriving

```cpp
// A crafted file with a wrong-length (here empty) salt must be rejected as
// corrupt up front, not fed into derive_key. Today it happens to fail closed via
// the later AEAD check only because the current Monocypher has no salt
// assertion; make the intent explicit and future-proof.
TEST(FileEncryption, RejectsMalformedSaltLength) {
  TempFile tmp("badsalt");
  writeRaw(tmp.path,
           "keyward-file-v1\nsalt=\ntoken=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n");
  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_THROW(s.get("token"), std::runtime_error);  // and must never crash/abort
}
```

### F3 — extend the memory-protection test to the derivation buffers (Linux)

`tests/secure_memory_protection_test.cpp` proves the *output* `Secret` is
mlock'd/guard-paged/`dd`. It does not cover the Argon2 work area or the transient
passphrase, which is exactly where F3 lives. Either (a) if `derive_key` is
changed to run Argon2 in a `secure_alloc`'d work area, add a smaps `lo`/`dd`
assertion on that buffer during derivation; or (b) if it is left as-is, add a
comment/test-doc note scoping the "never swapped" claim to the key only, so the
threat-model wording and the test agree. No new passing test is possible for the
plain-`std::vector` case — the point is that it *cannot* pass, which is the
finding.

---

### Triage priority

1. **F1** — CONFIRMED, incl. the laundering escalation *and* the `list()`/
   `remove()` breadth (enumeration poisoning + destructive plaintext rewrite).
   Land the four F1 regression tests, then decide the migration policy. This is
   the one that breaks a stated guarantee and turns one write into permanent
   substitution or destruction of the whole store.
2. **F2** — CONFIRMED. Binary-safe the plaintext tier or forbid `Vault` blobs in
   it; add the round-trip + end-to-end Vault tests.
3. **F6** — CONFIRMED. Bind the cached key to its salt (re-derive or hard-error
   on mismatch); land the consistency test. Cheap, prevents silent file
   corruption.
4. **F3/F5/F7** — cheap hardening + doc-scoping (secure/derivation buffers,
   salt-length check, length-field guard).
5. **F4** — doc note.
