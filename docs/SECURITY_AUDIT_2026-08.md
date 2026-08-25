# keyward — deep security audit findings (2026-08)

A fresh, read-only adversarial review of the keyward credential SDK, run per the
runbook in [adversarial_review.md](adversarial_review.md) against the current
`main`. Disposition: assume the code is broken and prove it. This report **does
not edit code or open PRs** — it is input for triage into fix-PRs.

**Scope covered.** Crypto composition (`secret_box`, `crypto_primitives`),
encrypted-file store + format (`file_secret_store`, `encrypted_file_format`),
untrusted-input parsers (`record_codec`, `base64`), key lifecycle / secure memory
(`secret`, `secure_memory`, `secure_string`, `key_provider`), the store
composition (`fallback_secret_store`, `default_store`), all three platform
backends (`keychain_*`, `windows_credential_*`, `secret_service_*`), and the
authenticator layer (`authenticator`, `passphrase_/biometric_/polkit_`, fallback).

**Attacker models** (from the runbook): **(A)** can read/write the stored files
(backup, disk image, sync folder); **(B)** a same-uid process; **(C)** feeds
crafted bytes to any parser.

**Method note.** Findings marked *verified* were read and confirmed at the cited
`file:line` in this pass. The three macOS-Critical findings, the file-store AAD
finding, the polkit refusal-downgrade, and the constant-time verifier were
each independently re-read against source. Dynamic verification (build / ASan /
fuzz run) was **not** performed — see "What I could not verify".

---

## Summary table

| # | Severity | Component | Title | Verified |
|---|----------|-----------|-------|----------|
| C1 | **Critical** | macOS Keychain | `get()` launders every `OSStatus` into "not found" → silent read-through to the (plaintext) file tier | ✅ read |
| C2 | **Critical** | macOS Keychain | `set()` ignores `SecItemAdd` result → silent write loss; `remove`-then-`add` is non-atomic (data loss) | ✅ read |
| C3 | **Critical** | macOS Keychain | `remove()` never verifies deletion → a credential reported revoked is not | ✅ read |
| H1 | **High** | Fallback compose | `set()` never invalidates the fallback copy → revoked/rotated secret persists in plaintext and resurfaces on any primary miss | ✅ read |
| H2 | **High** | Fallback compose | `remove()` skips the fallback tier when the primary throws → plaintext copy survives a revoke | ✅ read |
| H3 | **High** | Windows CredMan | `list()` frees every enumerated credential blob (all plaintext) without scrubbing | ✅ read |
| M1 | **Medium** | Encrypted file store | Entry **name** is not bound as AEAD associated data → cross-entry substitution / relabeling | ✅ read |
| M2 | **Medium** | polkit auth | An interactive user **refusal/cancel** can map to `Unavailable` → downgrades to the passphrase tier | ✅ read |
| M3 | **Medium** | Passphrase auth | Argon2id access-gate cost (8 MiB) is below current offline-cracking floors for an exfiltratable verifier | ✅ read |
| M4 | **Medium** | Linux Secret Service | `remove()` short-circuits its survivor check on a partial (multi-collection) delete | ⚠ agent |
| M5 | **Medium** | Linux Secret Service | `get()` silently prefers a readable duplicate over a **newer** unreadable one | ⚠ agent |
| M6 | **Medium** | Fallback compose | No `list()` override → `Vault::list()` throws `std::logic_error` on macOS and Linux | ✅ read |
| M7 | **Medium** | macOS Keychain | Invalid UTF-8 in a name → `CFRetain(NULL)` process crash (one-input DoS) | ✅ read |
| M8 | **Medium** | Windows CredMan | TOCTOU on the bare `<app>` target can delete another tool's (`keyring`) credential | ⚠ agent |
| L1 | Low | Key provider | `KEYWARD_PASSPHRASE` retained as a long-lived plaintext `std::string` for the store's lifetime | ✅ read |
| L2 | Low | Secret | Constructor deref of `nullptr` when `secure_alloc` fails (DoS, fails closed) | ✅ read |
| L3 | Low | Passphrase auth | `make_passphrase_verifier` accepts an empty passphrase (weak enrollment) | ✅ read |
| L4 | Low | Backends | Destructive non-atomic upsert on macOS & Linux (`remove`-then-`add`/`store`) | ✅ read |
| L5 | Low | macOS Keychain | No `kSecAttrAccessible` / ACL set — falsifies the "Keychain ACL" doc claim | ✅ read |
| L6 | Low | CLI prompter | Gathered secret left in an unwiped local `std::string` in `read_line` | ✅ read |
| L7 | Low | Biometric auth | Lockout / "enter password" fallback both → `Denied` (strands passphrase tier; fails closed) | ⚠ agent |
| L8 | Low | Fallback (both) | Constructors accept null tiers with no guard | ✅ read |
| I1 | Info | Backends | Secrets land in swappable `std::string` on all three read paths (interface-imposed residual) | ✅ read |
| I2 | Info | Windows CredMan | Secret **length** disclosed in a `std::length_error` message | ✅ read |
| I3 | Info | Encrypted file store | Salt / version / magic are unauthenticated (DoS / fail-closed only; folds into M1's fix) | ✅ read |
| U1 | Unverified | Windows CredMan | `CredEnumerateW` uses an undocumented **leading** wildcard filter | needs Windows |
| U2 | Unverified | Linux Secret Service | Locked-search fail-closed logic assumes gnome-keyring behaviour | needs KWallet/KeePassXC |

**Headline.** The Linux and Windows backends were hardened in earlier passes and
mostly hold. The **macOS Keychain backend was never updated past the Phase-0
scaffold** and violates the "no error laundering / verify remove / fail-closed"
invariants in the most direct way possible — `docs/THREAT_MODEL.md:82`'s
"macOS Keychain ✅" is not currently true. The crypto core (nonce uniqueness,
parser bounds, constant-time compare, AEAD fail-closed) **resisted** every attack
tried — with the single exception of M1 (name-binding).

---

## Critical

### C1 — macOS Keychain `get()` turns every error into "not found", downgrading to the file tier
**Location:** `src/keychain_secret_store.cpp:41-43`
```cpp
const OSStatus st = SecItemCopyMatching(q, &result);
CFRelease(q);
if (st != errSecSuccess || result == nullptr) return std::nullopt;   // ← every error == "absent"
```
**Attacker model:** B (and any headless/locked session). **Attack:** SSH into a
Mac, run under `launchd`, or hit a locked login keychain / screen-lock. The
Keychain returns `errSecInteractionNotAllowed` (-25308), `errSecAuthFailed`,
`errSecUserCanceled`, `errSecMissingEntitlement` (sandboxed / hardened runtime),
or a `securityd` XPC failure — **all** collapse to `std::nullopt`. There is no
`errSecItemNotFound` special-case; `errSecSuccess` is the only status
distinguished, and the `OSStatus` is dropped at line 43. `defaultSecretStore`
puts a `FileSecretStore` behind the Keychain (`src/default_store.cpp:90-91`) and
`FallbackSecretStore::get` (`src/fallback_secret_store.cpp:12-13`) then reads that
tier — **plaintext by default** (no `KEYWARD_PASSPHRASE`), and with **no**
plaintext warning (that warning only fires in the sole-tier branch, never behind
a keychain). This is exactly the downgrade Linux's `SecretServiceLocked` test
exists to prevent.
**Impact:** a "couldn't access the vault" is silently answered from a weaker (or
stale legacy-plaintext) store, or as "no such credential." **Confidence: high**
(read + traced through the compose layer).
**Fix direction:** mirror Windows `readCredential` — `errSecItemNotFound` is the
*sole* `nullopt`; every other status throws `std::runtime_error` carrying the
numeric status + `SecCopyErrorMessageString` text (never the value). Add a
locked-keychain regression test (create a throwaway keychain with
`SecKeychainCreate`, lock it) analogous to `tests/secret_service_locked_test.cpp`.

### C2 — macOS `set()` ignores `SecItemAdd`; the upsert is non-atomic
**Location:** `src/keychain_secret_store.cpp:51-60` (esp. `remove(name);` :52 and
`SecItemAdd(q, nullptr);` :57 — return value discarded as an expression statement)
**Attack:** in a locked/headless session, `set("token", rotated)` runs `remove`
(also unchecked), then `SecItemAdd` fails (`errSecInteractionNotAllowed`,
`errSecDuplicateItem`, `errSecAuthFailed`). `set()` returns **normally** — the app
believes the rotation is stored. The next `get()` returns `nullopt` from the
Keychain (C1) and the chain serves the **old** value from the file tier (H1),
possibly a revoked credential, indefinitely and with no error.
**Secondary — data loss:** because `set` deletes first, in an *unlocked* session
where the delete succeeds but the add then fails, the previous secret is destroyed
and the new one was never written — permanent credential loss reported as success.
**Confidence: high.**
**Fix direction:** check `SecItemAdd`'s status; throw on anything but success.
Prefer `SecItemUpdate` then `SecItemAdd`-on-`errSecItemNotFound` so a failure
never empties the slot.

### C3 — macOS `remove()` never verifies deletion
**Location:** `src/keychain_secret_store.cpp:62-66` — `SecItemDelete(q);` (return
discarded; the comment `// errSecItemNotFound is fine` shows only one status was
considered, but none can actually be distinguished).
**Attack:** an incident-response script revokes a leaked token; the keychain is
locked (screen-lock / SSH). `SecItemDelete` returns `errSecInteractionNotAllowed`
and `remove()` returns normally. The token remains and is served once the session
unlocks. This is the exact defect fixed on Linux
(`secret_service_store.cpp:216-243`) and advertised in `THREAT_MODEL.md`
("`remove` verifies rather than trusting a silent no-op") — but only Linux got
the fix. **Confidence: high.**
**Fix direction:** capture the status; `errSecItemNotFound` → return;
`errSecSuccess` → confirm with a follow-up `SecItemCopyMatching`; anything else →
throw.

---

## High

### H1 — `FallbackSecretStore::set()` leaves a stale plaintext copy in the fallback tier
**Location:** `src/fallback_secret_store.cpp:16-18` — `primary_->set(...)` only; the
in-code comment concedes "the fallback copy just goes stale."
**Attack:** a secret exists in the legacy 0600 plaintext file. The user rotates
it → the new value goes to the Keychain/keyring only; the **old plaintext stays on
disk forever**. Any primary miss resurrects it: a macOS Apple-ID-password change
(which renames the old login keychain and creates an empty one), a deleted
keychain item, a new `app` namespace, or any C1 laundering path. `get()` then
silently returns the revoked value. Under model A (backup / sync copy) the revoked
credential is also recoverable from disk long after "revocation."
**Confidence: high.**
**Fix direction:** after a successful `primary_->set`, `fallback_->remove(name)`
(escalate a hard error rather than swallow it). Migration means *moving*, not
copying.

### H2 — `FallbackSecretStore::remove()` skips the fallback tier when the primary throws
**Location:** `src/fallback_secret_store.cpp:20-23` — `primary_->remove(name);`
then `fallback_->remove(name);` with no try/catch.
**Attack:** Linux with a locked keyring: `SecretServiceStore::remove` correctly
throws; the exception propagates out of line 21 and **line 22 never runs**, so the
plaintext file copy survives. The caller sees "keyring locked," plausibly retries
later after unlocking, and the file copy is forgotten. Combined with H1 (that copy
may be pre-rotation), the plaintext tier accumulates revoked credentials no
`remove()` path reaches. Loud failure caps severity; the residue is silent.
**Fix direction:** remove from the weaker tier first, or run both and rethrow the
first error — never leave the weaker tier holding a value the caller deleted.

### H3 — Windows `list()` frees all enumerated credential blobs without scrubbing
**Location:** `src/windows_credential_store.cpp:212-226` — `CredFree(creds);` (:226)
with no `SecureZeroMemory`.
**Attack:** `CredEnumerateW` returns full `CREDENTIALW` structs including
`CredentialBlob` — the **plaintext of every credential in the namespace**.
`list()` reads only `TargetName` and frees the buffer unscrubbed, leaving the
whole namespace's secrets in freed heap (recoverable via a later allocation, a
crash dump, or the pagefile). In scope under THREAT_MODEL's "accidental in-process
leakage." The asymmetry is the proof: `readCredential` (:121-125) *does* scrub,
with a comment noting `CredFree` doesn't zero — `list()` frees a strictly larger,
secret-bearing buffer without it. **Confidence: high** (agent-reported; asymmetry
independently confirmed against the scrub in `readCredential`).
**Fix direction:** loop over `creds[i]`, `SecureZeroMemory` each non-null
`CredentialBlob` for `CredentialBlobSize` bytes before `CredFree`. (The Win32 API
has no names-only enumeration, so scrubbing is the available mitigation.)

---

## Medium

### M1 — Encrypted file store: entry name is not bound as AEAD associated data (cross-entry substitution)
**Location:** `src/secret_box.cpp:62,79` (both AEAD calls pass `nullptr, 0` for
AAD) via `src/file_secret_store.cpp:328,368,374`.
**Attacker model:** A / C (file-write access — the file tier's *exact* threat:
headless/CI, sync folder, restored backup). **Attack:** the encrypted file holds
`name = nonce‖mac‖cipher` per entry, all under one shared key. The AEAD
authenticates the value but **nothing binds it to its name**. An attacker with
file-write access swaps the `name=` labels of two authentic entries within one
file:
```
# before                          # after (labels swapped, ciphertext untouched)
prod-token=<base64 blob_P>        prod-token=<base64 blob_S>
staging-token=<base64 blob_S>     staging-token=<base64 blob_P>
```
Each blob still MAC-verifies under the shared key, so `get("prod-token")` returns
the authentic secret that was stored under `staging-token` — **no exception**,
`aead_open` succeeds. The app authenticates to prod with the staging token (or
vice versa). F1's `guardDowngrade` stops plaintext-*format* injection but not this
same-format relabel; `TamperedEntryThrows` only flips a ciphertext byte (which
breaks the MAC), so no existing test covers it. **Confidence: high** (all AEAD
call sites grepped; no AAD anywhere; test gap confirmed).
**Fix direction:** bind the entry name — and ideally the salt + format version —
as AEAD associated data in `aead_seal`/`aead_open` (Monocypher's `crypto_aead_lock`
takes an AD pointer/length already passed as `nullptr, 0`). Relabeling then fails
closed. Bump the file format version; add a swap-two-entries regression test.

### M2 — polkit maps an interactive refusal/cancel to `Unavailable`, downgrading to the passphrase tier
**Location:** `src/polkit_authenticator.cpp:103-117` (esp. :107 and :117)
**Attack:** `FallbackAuthenticator{Polkit, Passphrase}`. A user is present, the
polkit dialog appears, and they **cancel/decline**. In common polkit versions this
returns a *result* with `is_authorized=false, is_challenge=true` → line 117
`return Authorization::Unavailable` → `FallbackAuthenticator` (`fallback_authenticator.hpp:20`)
runs the passphrase tier. Separately, the cancel guard at :107 matches only
`G_IO_ERROR / G_IO_ERROR_CANCELLED`; a user dialog-cancel is typically surfaced in
the **polkit/D-Bus error domain** (`org.freedesktop.PolicyKit1.Error.Cancelled`),
which fails that match and falls to :109 `Unavailable`. The GCancellable path that
*looks* like it handles cancel only fires when keyward itself cancels — and it
passes `nullptr`, so it never does. Net: a present, refusing user is offered a
weaker tier instead of being denied. **Severity: Medium, High if a strictly-weaker
passphrase sits behind it.** Correctness depends on unpinned polkit behaviour.
**Confidence: medium** (code path confirmed at :117; the "refusal returns
is_challenge=true" premise is version-dependent and should be reproduced).
**Fix direction:** distinguish "no auth agent registered" (probe agent presence,
or only degrade when `allow_interaction_==false`) from "interaction ran and was
declined"; broaden cancel detection to the polkit error domain; map a declined
interactive challenge to `Denied`/`Cancelled`, not `Unavailable`. Verify polkit's
actual returns on dialog-cancel and on auth-failure empirically first.

### M3 — Argon2id access-gate cost is below current offline-cracking floors
**Location:** `src/passphrase_authenticator.cpp:20-21` — `kBlocks=8192` (8 MiB),
`kPasses=3`, lanes 1.
OWASP's Argon2id floor is ≈19 MiB (t=2) / 46 MiB (t=1); 8 MiB is under it. The
verifier blob (`salt‖hash`) is explicitly meant to be stored at rest
(`passphrase_authenticator.hpp:11-13`), i.e. exfiltration is the *expected* threat,
not hypothetical — the at-rest blob is exactly what an offline cracker gets.
**Fix direction:** raise memory to ≥19 MiB, calibrate passes to the unlock-latency
budget, and version the cost parameters into the stored blob so they can be raised
without invalidating existing verifiers.

### M4 — Linux `remove()` short-circuits verification on a partial delete
**Location:** `src/secret_service_store.cpp:225` — `if (removed) return;`
**Attack:** duplicate items with the same `{service, username}` routinely exist
(that is why `get` uses `search`, per its own comment at :118-123). Put one
duplicate in the unlocked default collection and one in a locked / non-default /
read-only collection. `secret_service_clear_sync` removes the unlocked one,
returns `TRUE` (a boolean, carrying no completeness info), and line 225 returns
immediately — the survivor check at :233-242 never runs. The caller is told the
credential is revoked; a later `get()` (which passes `SECRET_SEARCH_UNLOCK`)
unlocks the other collection and returns the "revoked" secret. **Confidence:
medium** (agent-reported; logic at :225 confirmed by read).
**Fix direction:** run the survivor search unconditionally — the check is already
written, just move it above the early return.

### M5 — Linux `get()` prefers a readable duplicate over a newer unreadable one
**Location:** `src/secret_service_store.cpp:156-180`
**Attack:** the fail-closed guard is `matched>0 && readable==0` (:177). If *some*
matching items are readable and some are not, the guard doesn't fire: :161
`if (!bytes) continue;` drops unreadable items before any timestamp comparison. A
stale readable duplicate in the unlocked default collection is returned as
authoritative while the current value — in a collection whose unlock the user
declined — is ignored, silently. The `modified` tiebreak can't help because the
unreadable item's timestamp is never consulted. **Confidence: medium** (agent).
**Fix direction:** track max `modified` over *all* matched items; if the winner is
unreadable, throw the locked-keyring error rather than serve an older readable
sibling.

### M6 — `FallbackSecretStore` has no `list()` override → `Vault::list()` throws on macOS & Linux
**Location:** `include/keyward/fallback_secret_store.hpp` (no `list()`) → inherits
the throwing default in `include/keyward/secret_store.hpp:26-28`.
`defaultSecretStore` returns a `FallbackSecretStore` on macOS
(`default_store.cpp:90`) and Linux-with-libsecret (:105), so `Vault::list()`
(`vault.hpp:44`) throws `std::logic_error` on both platforms — even though both
tiers *can* enumerate (`secret_service_store.cpp:245`, `file_secret_store.cpp:409`
are implemented and tested). Only Windows and the no-vault BSD path work. Every
existing `list()` test hits a concrete backend directly, so nothing catches this.
This is correctness, not style: the naive "return only the primary's names" fix
would produce exactly the incomplete list the contract forbids.
**Fix direction:** override `list()` to union both tiers' names and propagate (not
swallow) either tier's failure.

### M7 — macOS: invalid UTF-8 in a name crashes the process (`CFRetain(NULL)`)
**Location:** `src/keychain_secret_store.cpp:13-16` (`cfstr`) consumed at :27-32.
`CFStringCreateWithBytes(..., kCFStringEncodingUTF8, ...)` returns `NULL` for
invalid UTF-8 (a lone `0x80`, overlong encoding, unpaired surrogate — trivially
produced from a filename or non-UTF-8 locale input). `CFDictionarySetValue` then
`CFRetain`s NULL (fatal), and `CFRelease(NULL)` at :29/:32 is likewise fatal.
Every `get`/`set`/`remove` routes through `baseQuery`, so it's a one-input DoS on
the whole store. Windows already validates (`toWide` uses `MB_ERR_INVALID_CHARS`
and throws) — macOS lacks the equivalent, so the two platforms disagree on the
contract for the same input. **Confidence: high.**
**Fix direction:** validate and throw the same `std::runtime_error` the Windows
path throws, before touching CoreFoundation.

### M8 — Windows `remove()` TOCTOU on the bare `<app>` target
**Location:** `src/windows_credential_store.cpp:192-201` — a `readCredential`
`UserName==name` check and `CredDeleteW` are two separate calls on a namespace
shared with Python `keyring`. Between them, a `keyring.set_password(app, other, …)`
writes a different credential to the same bare `<app>` target (keyring's documented
"newest-for-service" behaviour). `CredDeleteW` has no conditional-on-username form,
so keyward deletes whatever is there now, destroying an unrelated credential. The
window is small but the interop design *guarantees* a concurrent writer exists.
**Confidence: medium** (agent).
**Fix direction:** re-read after delete and restore/flag if a different `UserName`
reappeared, or don't delete the bare target at all and report it to the user.

---

## Low / Info

- **L1 (Low) — `KEYWARD_PASSPHRASE` kept as a long-lived plaintext `std::string`.**
  `src/default_store.cpp:30-32`: `envKeyProvider` moves the passphrase into a
  lambda capture that lives for the store's lifetime — a swappable, un-wiped plain
  heap copy, contradicting the "passphrase only transiently plaintext, wiped after
  derive" hardening the interactive path applies (`key_provider.cpp:18-23`). The
  env var itself is also readable via `/proc/self/environ` and inherited by
  children (inherent to the on-ramp). *Fix:* hold it in a `Secret`, derive on each
  `unlock`, and wipe the source copy; document the env residual.
- **L2 (Low) — `Secret` derefs `nullptr` when `secure_alloc` fails.**
  `include/keyward/secret.hpp:24-27`: `secure_alloc` (→ `sodium_malloc`) can return
  `nullptr` (mlock quota, huge input, no secure pages), but the ctor does
  `if (size_) std::memcpy(data_, …)` with `data_==nullptr` → crash. Reachable from
  `Secret secure_entered(*entered)` on an attacker-influenced passphrase length.
  Fails closed (crash, no grant) → DoS, not bypass. *Fix:* throw a non-secret
  error or enter a defined empty state on allocation failure.
- **L3 (Low) — empty passphrase accepted at enrollment.**
  `src/passphrase_authenticator.cpp:40-43`: no minimum-length/non-empty check, so a
  verifier built from `""` unlocks on `""`. (`verify_passphrase` correctly rejects
  an empty/malformed *stored* blob via its size check, so at-rest forgery is
  closed — this is purely weak enrollment.) *Fix:* enforce a policy minimum, or
  document that the caller owns strength policy.
- **L4 (Low) — destructive non-atomic upsert on macOS & Linux.**
  macOS `set` (`keychain_secret_store.cpp:52`) and Linux `set`
  (`secret_service_store.cpp:196`) delete before writing; a failure between the two
  destroys the old secret with no replacement. (Linux's pre-delete only exists to
  collapse duplicates; the underlying store is already an upsert.) *Fix:* store
  first, then clear surviving duplicates.
- **L5 (Low) — no `kSecAttrAccessible` / ACL on macOS; falsifies a doc claim.**
  `src/keychain_secret_store.cpp:51-60` sets no accessibility class, no
  `SecAccessRef`/ACL, no data-protection opt-in. `SECURITY_ASSESSMENT.md:42` claims
  "Keychain ACL" — there is no ACL code. Not catastrophic (legacy file keychain
  grants the creating binary) but the protection class is unstated. *Fix:* set the
  attributes explicitly, or correct the assessment.
- **L6 (Low) — CLI prompter leaves a gathered secret unwiped.**
  `src/cli_prompter.cpp:42-45,74`: `read_line` returns the masked value in a plain
  local `std::string` that is never wiped (the Vault wipe guard only reaches
  `PromptField::value`). Bounded residual, same class as the documented "gathered
  prompt values." *Fix:* wipe the local, or gather straight into a `SecureString`.
- **L7 (Low) — macOS biometry lockout / "enter password" → `Denied`.**
  `src/biometric_authenticator.cpp:38,45-50`: `LAErrorBiometryLockout` and
  `LAErrorUserFallback` fall into `else → Denied`, which does *not* fall through, so
  a locked-out user is stranded even with a passphrase tier present. Inverse error
  (over-denying) — fails closed, not a bypass; asymmetric vs Windows (defaults to
  `Unavailable`). *Fix:* map lockout/user-fallback to `Unavailable` so the tier is
  reachable.
- **L8 (Low) — fallback constructors accept null tiers.**
  `fallback_secret_store.cpp:7-9` and `fallback_authenticator.hpp:14-16` move both
  pointers in without a null check → null-deref on first use. *Fix:* throw
  `std::invalid_argument` in the constructor.
- **I1 (Info) — secrets land in swappable `std::string` on all read paths.**
  `keychain_secret_store.cpp:45`, `windows_credential_store.cpp:119`,
  `secret_service_store.cpp:110`. The careful `SecureZeroMemory` /
  `secret_value_unref` hygiene is undone by the copy that outlives it; on Linux the
  *losing* duplicate copies (`get`) are also destroyed unwiped. THREAT_MODEL:67-70
  already flags the `get`-returns-`std::string` residual; the un-wiped duplicates
  are the part not mentioned. Interface-imposed until `SecretStore::get` returns a
  `Secret`.
- **I2 (Info) — secret length disclosed in an exception.**
  `src/windows_credential_store.cpp:151-155` puts `std::to_string(value.size())`
  into a `std::length_error` that is typically logged. Length is metadata about a
  secret. *Fix:* drop the size from the message.
- **I3 (Info) — file salt / version / magic are unauthenticated.**
  `src/encrypted_file_format.cpp`: swapping the salt only breaks decryption
  (fail-closed DoS), so this is low-impact on its own, but it should be closed
  together with **M1** by binding salt + version into the AEAD associated data.

---

## What resisted every attack (checked and clean)

- **Nonce uniqueness (the #1 target).** The file store generates a fresh random
  24-byte XChaCha20 nonce per entry and per re-seal (`file_secret_store.cpp:367,373`
  via `random_bytes` → libsodium `randombytes_buf`), and `seal()` a fresh salt+nonce
  per call (`secret_box.cpp:90-93`). 192-bit random nonces under a shared key are
  the XChaCha construction's designed use; collision probability is negligible. No
  reuse path found, including legacy migration.
- **Parser memory safety / fail-closed.** `decode_fields`
  (`record_codec.cpp:46-70`) does all length arithmetic as guarded `size_t`
  subtraction (`blob.size()-i < len` with `i<=blob.size()` maintained); a 4-GiB
  length field just returns `nullopt`. `base64_decode` (`base64.cpp:51-81`) rejects
  non-multiple-of-4 input, validates padding position, and fails closed on any bad
  char. `parse_encrypted_file` fails closed on a missing magic line, bad base64, or
  a non-blank line without `=`. `aead_open` rejects `sealed` shorter than a MAC and
  never throws. Consistent with the CI fuzzing of `decode_fields` and `unseal`.
- **AEAD fail-closed.** Wrong key/nonce or any tamper → `crypto_aead_unlock` rc≠0 →
  `nullopt` → the file store throws (`file_secret_store.cpp:329-331`). F1
  format-downgrade guard (`guardDowngrade`) refuses a non-encrypted file for an
  encrypted store unless migration is explicitly opted in.
- **Constant-time passphrase verify.** `verify_passphrase`
  (`passphrase_authenticator.cpp:45-51`) checks the verifier size, then compares via
  `secure_equal` → `sodium_memcmp` — no early-exit, no `std::string ==`, no all-zero
  shortcut; the derived hash is `secure_zero`'d and the entered passphrase is held
  in a `Secret` with the plain copy wiped.
- **`FallbackAuthenticator` chaining.** Only `Unavailable` degrades; `Denied` and
  `Cancelled` are returned verbatim (`fallback_authenticator.hpp:19-21`). The one
  live invariant-1 concern (M2) is the polkit *source* mislabelling a refusal, not
  the chaining. `Vault` gates synchronously immediately before the load
  (`vault.hpp:64,75,89`) with no cache today — no exploitable TOCTOU in scope.
- **Windows backend (mostly).** `readCredential` is the reference "no error
  laundering" shape (`ERROR_NOT_FOUND` → `nullopt`, else throw); blob-size
  fail-closed at exactly `CRED_MAX_CREDENTIAL_BLOB_SIZE`; correct
  size-then-fill / `CredFree` ownership; `MB_ERR_INVALID_CHARS` UTF-8 validation;
  no secret values in messages (bar I2). The CredMan-only, no-file-fallback
  decision (`default_store.cpp:92-99`) is sound.
- **Linux backend (mostly).** `get` fails before any `nullopt` on a GError; the
  fully-locked case fails closed and is regression-tested; `remove` verifies on the
  no-error path; RAII deleters match libsecret transfer semantics (no double/UAF);
  binary values preserve embedded NULs; the newest-wins/ambiguity logic traced
  order-independent. The residual gaps are the *partial-collection* cases M4/M5.
- **Secure-memory build wiring.** The CMake feature-detection
  (`CMakeLists.txt:32-73`) force-enables libsodium's page-protection primitives that
  the wrapper otherwise leaves off, and `tests/secure_memory_protection_test.cpp` is
  the loud regression backstop for the previously-silent failure.

---

## What I could not verify (did not attack / needs an environment)

- **No dynamic run.** I did not build, run the test suite, run ASan/UBSan/LSan, or
  run the fuzzers in this pass — all findings are from static reading. The macOS
  `OSStatus` behaviours (C1–C3) are argued from the API contract, not observed on a
  locked keychain.
- **U1 — Windows `CredEnumerateW` leading-wildcard filter** (`windows_credential_store.cpp:206-212`,
  `"*@<app>"`). The Win32 docs describe a *trailing*-only wildcard; a leading one is
  undocumented. CI (`windows-latest`) asserts `list()` returns both names, so the
  runtime evidently accepts it — but this relies on undocumented behaviour that
  could regress to an incomplete list (which the contract forbids) or a throw. Needs
  a Windows box to settle: `CredEnumerateW(L"*@x", 0, &n, &c)` and check
  `GetLastError()`.
- **U2 — Linux locked-search assumption on non-gnome providers**
  (`secret_service_store.cpp:130-134,227-232`). The fail-closed reasoning rests on
  "a locked collection still answers attribute searches." Spec-grounded and true for
  gnome-keyring (the only daemon tested), but a provider that exposes no collection
  while locked (some KWallet / KeePassXC configs) yields `matched==0` → `get`
  returns `nullopt` → downgrade to the plaintext file. Needs a run of
  `run_isolated_keyring.sh` against KWallet / KeePassXC.
- **macOS backend has no test coverage at all** — there is no keychain equivalent of
  the Windows/Linux backend tests, so none of C1–C3, M7, L4, L5 are caught by CI.
- **Cross-tool interop** (`keyring`) and **multi-thread concurrency** on a shared
  `SecretStore` were read but not exercised; no backend documents a thread-safety
  contract.

---

## Suggested triage order

1. **C1–C3 (macOS backend)** — rewrite error handling to match the Windows
   reference; add a locked-keychain regression test. This is the single biggest gap
   and it silently voids the macOS guarantee.
2. **H1–H2 (fallback compose)** — make `set` evict the fallback copy and `remove`
   reach both tiers; these turn "revocation" into a lie across all platforms.
3. **M1 (file-store AAD)** — bind name+salt+version as associated data; bump the
   format version. Closes cross-entry substitution and I3 at once.
4. **H3, M7 (memory-safety / DoS)** — scrub the Windows `list()` blobs; validate
   UTF-8 on macOS.
5. **M2, M3 (auth)** — fix the polkit refusal downgrade and raise the Argon2 cost.
6. Remaining M/L/Info as capacity allows; settle U1/U2 on their platforms.

Record refuted findings too, so a later pass doesn't re-litigate the "resisted"
list above.
