# keyward — encryption at rest for the file store (scope, not an implementation)

`FileSecretStore` writes secrets in plaintext. `seal`/`unseal` — Argon2id +
XChaCha20-Poly1305 — exist, are tested, and are now fuzzed, with **zero callers**.
This document scopes joining them up, and puts the decisions that block it in
front of a human. Nothing here is built yet.

## Where things actually stand

Verified rather than assumed:

```
$ cat -v /tmp/kw-fsprobe/creds
jira=SUPER-SECRET-TOKEN-12345
-rw------- 1 bernardo-cohen bernardo-cohen 30
```

- `FileSecretStore` stores `NAME=value` lines, `0600` file inside a `0700` dir.
- `grep -rn 'seal(' src include` outside `secret_box.cpp` → **0 hits**.
- There is **no format version byte** anywhere in the codebase.
- One `seal` costs **~2.2 s**; one `unseal` costs **~2.2 s** (Argon2id, 100 MB,
  3 passes, measured on this machine). This number drives most of the design.

The file store's own header is honest about the gap ("SECURITY CEILING: values
are stored in PLAINTEXT — 0600 is access control, not encryption"). Two other
documents are not: `DESIGN.md` describes the tier as "encrypted file", and the
security invariants say a file store "encrypts at rest with a vetted AEAD".
Whatever is decided here, that inconsistency should be resolved — either by
building this or by correcting those two claims.

## What encryption actually buys

Worth being precise, because `0600` already does some of this work.

**Gains:** the file surviving contact with a backup, `rsync`, a git repo, a cloud
sync folder, or a disk image; a stolen machine without full-disk encryption; a
support bundle someone pastes.

**Does not gain:** protection from `root`, from same-user code while the key is
cached in memory, or from a keylogger. A same-user attacker on a live unlocked
session still wins.

So the honest framing is **"protects the file once it leaves the machine, or
while the machine is off"** — not "protects the secret from local attackers".
That framing matters, because it also tells you the feature is not worth much
friction at the prompt.

## Blast radius per platform

| Platform | File store's role | Effect of encrypting it |
|---|---|---|
| Linux **without** libsecret, BSD, other | **Sole tier** — the only place secrets live | Largest gain; also the only place a bad UX decision is unavoidable |
| Linux **with** libsecret | Fallback behind the keyring | Legacy entries only — `FallbackSecretStore::set` writes to the primary, so the tier drains as entries are rewritten |
| macOS | Fallback behind the Keychain | Same as above |
| Windows | **Not used at all** — `defaultSecretStore` returns Credential Manager only | None |

Two consequences. First, this is not a Linux-only change: macOS reads that tier
too, so it cannot be scoped as "Linux hardening". Second, the urgent case is
narrow — a Linux box without libsecret, or a BSD — because everywhere else the
tier only holds entries that predate the native vault.

> **Sequencing note (2026-08-20).** keyward is a library others embed or bind, so
> `KeyProvider` has to cross a C boundary that does not exist yet. See
> [EMBEDDABILITY.md](EMBEDDABILITY.md) — that work comes first, and it also settles
> Decision 5: encryption is **opt-in**, because an embedded library must never
> start prompting inside someone else's app.

## Decision 1 — where does the key come from?

This is the blocker. Four candidates:

**A. Reuse the passphrase from `PassphraseAuthenticator`.** The user already
types it, and there is only one secret to remember.
*Against:* `Authenticator::authorize` returns `Authorization` — an
allow/deny verdict with **no channel for key material** — and
`PassphraseAuthenticator` deliberately discards the passphrase after checking it
against its Argon2 verifier. Widening that return type would conflate "may this
caller proceed" with "here is a key", and `NoAuth` and `BiometricAuth` have no
key to hand back, so the file store would break under those policies.

**B. A separate `KeyProvider` seam.** A small interface of its own —
conceptually `std::optional<Secret> unlock(std::string_view reason)`. The
`PassphraseSource` type this needs *already exists*
(`std::function<std::optional<std::string>(std::string_view prompt)>`, in
`passphrase_authenticator.hpp`). Composes with any `Authenticator`, and keeps the
gate and the key as separate concerns.
*Against:* one more seam to explain, and the user may end up with two prompts
(authorize, then unlock) unless they are deliberately wired to one source.

**C. Random data key wrapped by the OS keychain.** Encrypt the file with a random
32-byte key and store *that key* in the OS keychain.
*Against:* **circular in the case that matters.** The file store is the sole tier
precisely when there is no keychain. It would add protection only where the
keychain already protects everything.

**D. Machine-bound key (TPM, `systemd-creds`).** No user interaction at all.
*Against:* platform-specific, heavy, and protects only against an offline
attacker who takes the file but not the TPM — which is roughly the disk-image
case. Plausible later; a large amount of new surface for a fallback tier.

**Recommendation: B.** It is the only option that works in the case that
actually needs it (no keychain available), keeps `Authenticator` honest as a
gate, and reuses a type that already exists.

## Decision 2 — whole-file or per-entry?

**Whole file:** one salt, one nonce, simplest to reason about.
*Against:* `list()` needs the key, so enumerating service names would prompt for
a passphrase. Every `set` rewrites and re-seals everything.

**Per entry** (`NAME=<base64 sealed blob>`): the line format survives, and
`list()` and `remove()` keep working **without the key** — they only touch names.
*Against:* names stay in plaintext.

Name leakage is acceptable and consistent: Secret Service stores its attributes
(`service`, `username`) in the clear too, so a service name is already not
treated as secret material anywhere in keyward. Callers who disagree can name
their entries opaquely.

**Recommendation: per entry**, with names left visible.

## Decision 3 — the 2.2-second problem

At production Argon2 cost, a naive per-entry `seal()` would mean:

- `get("jira")` → one `unseal` → **~2.2 s**
- `set` on a five-entry file → re-seal each → **~11 s**

Unusable. The fix is structural, not a cost reduction: **derive the key once, per
file, and cache it** in `Secret` (libsodium secure memory) for the lifetime of
the store object. That means a **file-level salt** stored in the header and a
**per-entry nonce**, with the AEAD applied per entry using the shared key. Key
reuse across entries is safe precisely because each entry gets a distinct nonce.

That does **not** fit the current `seal`/`unseal` signatures, which derive a key
from a passphrase on every call. This needs a lower-level pair — roughly
`derive_key(passphrase, salt) -> Secret` plus `aead_seal/aead_open(key, nonce, …)`
— with `seal`/`unseal` kept as the one-shot convenience built on top. That is the
single largest piece of work here, and it touches crypto code, so it wants its
own review rather than being smuggled in.

Cost then becomes one ~2.2 s unlock per process (or per TTL window), which is the
same shape as the authenticator's planned TTL caching and should probably share
it.

## Decision 4 — format and migration

There is no version byte today, so this has to be introduced. Sketch:

```
keyward-file-v1
salt=<base64, 16 bytes>
jira=<base64 sealed entry>
```

A file whose first line is not the magic is a **legacy plaintext file**. Reading
must keep working; the natural upgrade is to re-encrypt on the next `set`,
mirroring how the keyring tiers already migrate entries forward.

Two things to settle: whether an encrypted store ever *silently* reads a legacy
plaintext entry (convenient, but a downgrade an attacker could induce by
truncating the header), and whether migration is automatic or explicit.

## Decision 5 — is it on by default?

`defaultSecretStore` currently builds `FileSecretStore` with a path and nothing
else. Encryption needs a key source, and there is no interactive one available in
a library constructor.

Options: keep the plaintext store as the default and let encryption be opt-in via
a constructor overload taking a `KeyProvider`; or make `defaultSecretStore`
require a provider on platforms where the file store is the sole tier. The first
is far less disruptive; the second is the one that actually closes the gap for
the users who need it.

**This is the decision I would not make alone**, because it changes the default
security posture and the first-run experience on exactly the platforms where
keyward is weakest.

## What I would build, in order

1. `derive_key` / `aead_seal` / `aead_open` beneath the existing `seal`/`unseal`
   (crypto change — own PR, own review).
2. `KeyProvider` seam + a `PassphraseSource`-backed implementation.
3. Versioned file format + legacy read path + migrate-on-write.
4. `FileSecretStore` encryption, opt-in by constructor.
5. Wire into `defaultSecretStore` — only after Decision 5.

Steps 1–4 are additive and break nothing. Step 5 is the behaviour change.

## Open questions

1. Key source — confirm **B** (`KeyProvider`), or prefer A/C/D?
2. Per-entry with visible names — agreed?
3. Should the cached key share the authenticator's TTL machinery, or hold for the
   lifetime of the store object?
4. May a store configured for encryption read a legacy plaintext entry, or should
   that fail closed and require explicit migration?
5. Opt-in, or default-on where the file store is the sole tier?
6. Until this ships: correct `DESIGN.md` and the security invariants to say the
   file tier is plaintext, so the documents stop disagreeing with the code?
