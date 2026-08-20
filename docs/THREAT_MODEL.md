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
  memory — guard-paged, `mlock`ed (never swapped) and `MADV_DONTDUMP`ed (never in
  a core dump), **verified at runtime** by
  `tests/secure_memory_protection_test.cpp`.
  This claim was previously **false in practice**: the CMake wrapper that fetches
  libsodium performs no feature detection, so libsodium compiled its fallback
  allocator and `sodium_malloc` behaved as plain `malloc`. Zeroing still worked,
  which is why nothing looked wrong — but secrets could reach swap and appeared in
  core dumps. keyward now detects the primitives and passes them through, and the
  regression test fails loudly if they ever go missing again.
- ✅ **The serialization path no longer leaks into freed heap.** `encode_fields`
  builds into a `SecureString` (`SecureAllocator` zeroes every block it
  releases). This closes a hole that end-of-life wiping *cannot* reach: a growing
  `std::string` copies its contents into a larger block on each reallocation and
  frees the old one untouched, so serializing a record scattered prefixes of it —
  secret values included — across freed memory, where `secure_zero(s.data(),
  s.size())` never went. `SecretStore::set` now takes a `std::string_view`, so
  handing the blob to a backend costs no plaintext copy either.
- ⚠️ **In-flight secrets are still not fully in secure memory.** What remains,
  narrowed: the **read** path (`SecretStore::get` returns a plain
  `std::string`, and `decode_fields` writes plain `std::string` field values) and
  **gathered prompt values** (`PromptField::value`, plus whatever the CLI/TUI
  holds internally). Those are single exact-size buffers that `Vault` does wipe
  before release, so the residue is bounded — unlike the growth case above — but
  the wire-through is not finished. Note also that `from_fields` writes into the
  caller's own struct members, which keyward cannot control; the `Sensitive` flag
  in a schema marks which of those matter.
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
- ✅ **File-store writes are atomic and durable.** The credentials file is
  replaced via a temp file + `rename` (POSIX) / `MoveFileEx` with
  `REPLACE_EXISTING|WRITE_THROUGH` (Windows), with `fsync` of both the file and
  the directory entry. It previously opened the real file with `std::ios::trunc`,
  so a crash, OOM kill or full disk mid-write left it empty or half-written —
  losing **every** credential in it, not just the one being stored — and two
  writers produced an interleaved file. The temp file is owner-only from the
  instant it exists, which also closes a window where the real file was briefly
  readable under the ambient umask. Pinned by
  `FileSecretStore.ReplacesTheFileRatherThanRewritingItInPlace`, which detects an
  in-place rewrite by its inode.
  Still outstanding: concurrent writers can *lose an update* (each does
  read-modify-write), which atomicity does not address — that needs advisory
  locking.
- ⚠️ **The file store writes plaintext.** `0600` is access control, not
  encryption — anyone who gets the file (backup, sync folder, disk image, support
  bundle) gets the secrets. `seal`/`unseal` exist and are fuzzed but have no
  callers. It is the **sole** tier on Linux without libsecret and on BSD; a
  drain-only legacy tier behind the keyring elsewhere; unused on Windows. Scoped
  in [FILE_ENCRYPTION.md](FILE_ENCRYPTION.md), blocked on where the key comes from.
- **Not independently audited.** Do not entrust other people's high-value secrets
  to keyward until it has been reviewed.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
