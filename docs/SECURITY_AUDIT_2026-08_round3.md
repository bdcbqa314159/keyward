# keyward — deep security audit findings (2026-08, round 3)

The third internal adversarial review, run per the runbook in
[adversarial_review.md](adversarial_review.md) against a `main` that already
carried every round-1 and round-2 fix. Run **blind**: three independent reviewers
worked from a checkout with the round-1 and round-2 findings reports removed, so
nothing anchored them to what was already known. Each reviewer took a different
slice deepest (crypto/parsers/file-store · platform backends/store/auth · key
lifecycle & cross-cutting) and did its own dynamic pass. This report is the
consolidated, deduped result. It **does not edit code** — it is the triage input
that became fix-PRs.

**Dynamic work across the three reviewers.** Clean `asan` preset builds (libsodium
page protections confirmed enabled at configure); the full suite run under
ASan+UBSan with **zero sanitizer diagnostics**; the libFuzzer harnesses run to a
combined **~4M executions** with no crash; plus custom ASan PoCs and a
3.5M-iteration parser stress. LSan is unsupported on macOS/ARM; the Windows and
Linux backends are `#if`-guarded off macOS and were reviewed statically only
(flagged per finding).

**Attacker models** (from the runbook): **(A)** can read/write the stored files
(backup, disk image, sync folder); **(B)** a same-uid process; **(C)** feeds
crafted bytes to any parser.

> **Headline: no Critical, no High.** The crypto core (nonce uniqueness incl. the
> migration re-seal, the v2 `version‖salt‖name` AEAD associated-data binding, the
> fail-closed parsers) and **every round-1/2 fix** held up under a fresh blind
> attack. The findings below are one Medium injection surface in the file tier,
> two Medium memory-hygiene gaps, and a tail of Lows/Infos — several of them
> consequences of round-2's own fixes.

> **Remediation status (all closed as of this report).**
> - **R3-1** → PR #69 · **R3-2, R3-4, R3-5, R3-8** → PR #70 · **R3-3** → PR #71 ·
>   **R1-F4** (fuzz coverage) → PR #72 · **R3-9** + accepted-residual documentation
>   → this PR.
> - The remaining Lows/Infos (**R3-10, R1-F3, R1-F5**) are documented as accepted
>   residuals below rather than fixed — see the rationale on each.

---

## Findings (consolidated, deduped, ranked)

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| R3-1 | **Medium** | default_store / file tier | Plaintext file fallback behind the OS vault is an injection surface — a planted `keyward-plain-v1` file is served as authentic for any key absent from the vault, no warning | fixed #69 |
| R3-2 | **Medium** | macOS Keychain | `get()` copies the `CFDataRef` then `CFRelease`s it without zeroing — plaintext lingers in freed CF heap (Windows/libsecret already scrub) | fixed #70 |
| R3-3 | **Medium** (libstdc++) | record codec / Fields | Short (SSO) field values shed by a `Fields` `push_back` realloc linger in freed heap; `wipe_fields` reaches only the live vector | fixed #71 |
| R3-4 | Low | Passphrase auth | `authorize()` can throw (bad_alloc from the 19 MiB Argon2 buffer, or a throwing source) — violates the no-throw authenticator contract | fixed #70 |
| R3-5 | Low | secret_box | `derive_key` doesn't null-check `secure_alloc` — a null result → Argon2 writes to `nullptr` (crash) | fixed #70 |
| R3-8 | Low | default_store | `KEYWARD_PASSPHRASE` never removed from `environ` → inherited by child processes | fixed #70 |
| R3-9 | Low | macOS Keychain | Accessibility class set only on `SecItemAdd`, not `SecItemUpdate` — an adopted foreign item keeps its weaker class | fixed (this PR) |
| R1-F4 | Info | fuzzing | The file store's read path (`parse_encrypted_file` → `aead_open`) wasn't a CI fuzz target; `unseal` fuzzes a framing with no production callers | fixed #72 |
| R3-10 | Low/Info | Fallback compose | `FallbackSecretStore::set` can leave a stale weaker-tier copy if eviction throws after the primary write | accepted (below) |
| R1-F3 | Info | base64 | `base64_decode` accepts non-canonical trailing bits (`QR==` ≡ `QQ==`) — malleability only | accepted (below) |
| R1-F5 | Info | file format | Entry names containing `=` or newline corrupt the line-based file format | accepted (below) |

---

## Accepted residuals (documented, not fixed)

- **R3-10 — `FallbackSecretStore::set` stale copy on eviction failure.** If the
  primary write succeeds and the fallback eviction (`remove`) then throws
  (disk-full / permission), the old value survives in the weaker tier. It is
  *shadowed* on read (primary wins) and `set()` rethrows, so the caller is
  informed. Since PR #69 removed the file tier from behind the OS vault, this is
  only reachable when a caller composes a `FallbackSecretStore` explicitly — a
  knowing choice. Not worth the awkward two-phase-commit machinery on a shadowed,
  caller-visible edge.
- **R1-F3 — non-canonical base64 trailing bits.** `base64_decode` doesn't require
  the unused low bits of a final group to be zero, so `QR==` and `QQ==` decode to
  the same byte. This is base64 *malleability* only: the decoded bytes are
  unchanged and everything downstream (salt, sealed entry) is AEAD-authenticated,
  so it grants no forgery. Length and padding *placement* are strictly checked.
- **R1-F5 — entry names with `=` or newline.** The line-based file format splits
  `name=value` on the first `=` and records on `\n`, so a name containing either
  mis-parses on read-back. Names are caller-chosen service identifiers, not
  attacker-controlled under the threat model; the OS vault backends store names as
  opaque attributes and are unaffected. Documented as a file-tier constraint on
  `FileSecretStore` (see its header). Moot as the file tier is retired.

## Still open — platform-gated, from round 2

These need real Windows / Linux hardware or specific desktop stacks to reproduce
and verify, so they are held for the platform agents rather than fixed blind from
macOS: **M2** (polkit refusal→Unavailable), **M8** (Windows `remove` TOCTOU on the
bare target), **L7** (biometric lockout→Denied), **U1** (Windows `CredEnumerateW`
leading-wildcard semantics), **U2** (Linux KWallet/KeePassXC locked-search
behaviour).

---

## What resisted (attacked by ≥1 reviewer, could not break)

- **Nonce uniqueness** — every seal path (one-shot `seal`, per-entry file `set`,
  and the legacy-migration re-seal under the shared file key) draws a fresh 192-bit
  random XChaCha nonce; no deterministic derivation anywhere.
- **AEAD associated-data binding** — a PoC that moved one entry's ciphertext under
  another name made `get()` throw (tag reject), not silently decrypt; cross-file
  replay is blocked by the per-file salt in both the AD and the key derivation.
- **Untrusted-input parsers fail closed** — `decode_fields` length arithmetic is
  overflow-safe, `base64_decode` rejects bad length/char/padding, and
  `parse_encrypted_file` rejects any malformed line. ~4M combined fuzz executions,
  no crash; full ASan/UBSan suite clean.
- **No secret VALUE in any exception / log** — grepped exhaustively; messages carry
  names, paths, numeric status and OS-supplied text only.
- **`Secret` move semantics** — move nulls the source, self-move guarded,
  `secure_free` zeroes; no double-free or leak under ASan.
- **Constant-time verify** — `sodium_memcmp` over the 32-byte hash, recomputed hash
  wiped; empty-passphrase enrollment rejected; verifier at the OWASP Argon2id floor.
- **Denied-vs-Unavailable contract** — `FallbackAuthenticator` degrades only on
  `Unavailable`; biometric/polkit map a real deny to `Denied`, so a denied strong
  factor cannot fall through to a weaker passphrase tier.
- **Backends don't launder errors into "not found"** — only the genuine miss code
  maps to absent; every other status throws, preventing a silent downgrade. Locked
  keyring / keychain fail closed; delete-verify present on all three.

## What could not be verified

- **Live Windows / Linux backends** were not compiled or executed on the macOS
  hosts — reviewed statically; the still-open round-2 findings above are why.
- **macOS Keychain at runtime** was exercised only via the host-gated round-trip on
  real hardware, not by every reviewer.
- **R3-3 end-to-end on libstdc++** — the SSO leak mechanism was confirmed against a
  faithful model and the fix is structural (`static_assert`-guarded); the CI Linux
  distro jobs run the real libstdc++.
