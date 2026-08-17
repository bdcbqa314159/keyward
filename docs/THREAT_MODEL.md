# keyward — threat model

What keyward defends, what it assumes, and — just as important — what it does
**not** protect against. keyward is a credential SDK; being explicit about the
boundary is part of the product.

## Assets

Application credentials — API keys, tokens, passwords — that an app hands to
keyward to store and retrieve.

## Trust model & assumptions

- A **single-user machine** running a **non-compromised OS**.
- The **OS credential vault** (macOS Keychain, Windows Credential Manager, Linux
  Secret Service) is trusted for at-rest protection — keyward delegates to it.
- The **calling process is trusted while it runs**: it legitimately holds the
  secret in order to use it.

## In scope — what keyward defends against

- **At-rest exposure / disk theft.** Secrets are stored in the OS vault
  (encrypted at rest, bound to the user). Where no vault exists, the
  encrypted-file backend (Argon2id + XChaCha20-Poly1305) protects a file under a
  passphrase.
- **Tampering / corruption of stored data.** AEAD authentication (encrypted
  file), a format-version byte, and bounds-checked parsing reject tampered,
  truncated, or foreign blobs instead of mis-parsing them.
- **Accidental in-process leakage.** `Secret` redacts itself in any textual form,
  compares in constant time (`sodium_memcmp`), and is held in libsodium secure
  memory (no-swap, guard-paged, zeroed on drop). Errors never carry secret
  material. Ambiguity **fails closed** — never a silent downgrade.
- **Timing side-channels** on secret comparison.

## Out of scope — what keyward does NOT defend against

- A **compromised process** that already holds the passphrase or a decrypted
  secret. Once your app reads `cred.token`, protecting it is the app's job.
- **root / kernel / hypervisor / physical-memory / cold-boot** attackers.
- The **security of the OS keychain itself** — that is Apple / Microsoft / GNOME's
  responsibility, and keyward's trust anchor.
- **Malware running as the same user.** The OS vault's access model is the
  boundary, not keyward.
- **Supply-chain compromise** of dependencies — mitigated by pinning
  (Monocypher, libsodium, FTXUI), not eliminated.

## Current hardening status (honest, pre-1.0)

- ✅ `Secret`, the derived encryption key, and the RNG run on libsodium secure
  memory.
- ⚠️ **In-flight secrets are not yet fully in secure memory.** Transient copies —
  stored record bytes and gathered prompt values — still pass through plain
  `std::string`. The exposure window is brief and in-process only, but it is not
  closed; the end-to-end wire-through is in progress.
- Backends: macOS Keychain ✅, Windows Credential Manager ✅, Linux Secret
  Service via libsecret ✅ (`0600` file remains the fallback everywhere).
- ✅ `decode_fields` is fuzzed in CI on every PR (libFuzzer + ASan, seeded corpus
  in `tests/fuzz/corpus/`, ~17k exec/s).
- ✅ **A locked Linux keyring fails closed.** A locked collection still answers
  searches — attributes readable, secrets withheld — so the backend used to read
  it as "no such secret" and, through `defaultSecretStore`'s fallback chain, drop
  to the plaintext file store. `get` now unlocks (prompting if the OS asks) and
  throws if the value is still unreadable; `remove` verifies rather than trusting
  a silent no-op that would tell a caller a credential was revoked when it was
  not. Regression test: `SecretServiceLocked.Isolated`, which runs against a
  throwaway keyring because locking a collection is a global act.
- ✅ **`unseal` is fuzzed in CI too.** It eats fully attacker-controlled
  ciphertext, so it matters more than `decode_fields`. It was previously
  unfuzzable at production KDF cost — Argon2id over a 100 MB buffer for every
  input past the 56-byte header, measured at 12 executions in 21 seconds. Fuzz
  builds now compile a token Argon2 cost (`KEYWARD_FUZZ_CHEAP_KDF`, set only
  under `KEYWARD_BUILD_FUZZERS`), giving ~6.5k exec/s over the *same* parse,
  length-arithmetic and AEAD-verify branches. Production builds on every OS are
  byte-identical with or without that option — verified by comparing object code.
  First deep run: 795,416 executions, no crashes.
  Note the seed blobs are sealed at production cost, so their MAC does not verify
  in a fuzz build; the fuzzer therefore covers parse-and-reject, not
  parse-and-accept. Mutation could never reach accept anyway (128-bit MAC), and
  the accept path is covered by `secret_box_tests` in a normal build.
- **Not independently audited.** Do not entrust other people's high-value secrets
  to keyward until it has been reviewed.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
