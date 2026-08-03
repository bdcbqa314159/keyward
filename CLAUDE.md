# keyward — working agreement

A small, modern-C++20 **credential-manager SDK**: a `SecretStore` interface with pluggable
backends (macOS Keychain, an encrypted file, and a fallback that chains them). This file is the
short version an agent/contributor reads each session. The conventions below — especially the
**security invariants** — are what any contributor (or agent) must respect.

> The maintainer's personal working mode ("learn-by-building") lives in the git-ignored
> `CLAUDE.local.md` — not needed to build or contribute; ignore it if you're not the author.

## Security invariants (load-bearing — get these right or the SDK is unsafe)

This is a *secrets* library; correctness here is security, not style. Every one of these is a
hard rule:

- **Secrets never leak into logs, errors, or string forms.** No secret in an exception message,
  no secret in `operator<<` / `.dump()` / a `Debug`-style print. A secret type **redacts itself**
  (`****`) in any textual representation.
- **Zeroize secret memory on destruction.** Overwrite the bytes before the memory is freed, and
  stop the compiler from optimizing the wipe away (`explicit_bzero` / `memset_s` /
  `SecureZeroMemory`, or a `volatile` write loop). A `Secret`/`SecureString` type wipes in its dtor.
- **Constant-time comparison** for secrets/tokens — never a short-circuiting `==` / `memcmp`
  (timing side-channel). Compare the full length every time.
- **Minimize copies and lifetime.** Move secrets, don't copy; hold them in memory as briefly as
  possible; no incidental copies left lying around.
- **Never hardcode or commit secrets.** They come from the Keychain / a file with strict perms
  (`0600`) / the environment — and a file store **encrypts at rest** with a *vetted* AEAD
  (libsodium / OpenSSL). **Don't roll your own crypto.**
- **Fail closed.** On any ambiguity (can't decrypt, keychain unavailable and fallback not
  permitted), refuse — never silently expose, skip, or downgrade.
- **Prefer no-swap for secret pages** (`mlock`) where feasible, so secrets aren't paged to disk.

## Conventions

- **C++20.** Value semantics by default; `unique_ptr` for single-owner resources.
  **No singletons, no shared_ptr-everywhere.**
- **Interfaces over hard-coding:** `SecretStore` is an abstract base; backends (`KeychainSecretStore`,
  `FileSecretStore`, `FallbackSecretStore`, `DefaultStore`) implement it. Keep the seam clean so a
  new backend slots in without touching callers.
- **Errors:** report failures as values or a typed exception at a well-defined boundary — but an
  error must **never carry secret material** (see invariants).
- Platform code (Keychain = macOS Security.framework) stays behind the interface; other platforms
  fall back to the file store.

## Build

CMake with presets (`debug` / `release` / `asan`), GoogleTest via `FetchContent` — mirror the
`mcp-cpp-sdk` setup. The `asan` build is especially valuable here (secret-lifetime / use-after-free
bugs are exactly what a credential store must not have). *(CMake not wired yet — see status.)*

## Git flow

Branch per milestone, small meaningful commits (short single-line messages, no co-author footers),
PR per milestone into `main` with CI green. The author writes the commits. Repo will be published.

## Where we are

Headers + sources exist for the `SecretStore` interface and the Keychain / file / fallback /
default backends, plus `tests/secret_store_test.cpp`. **Not yet wired:** a top-level `CMakeLists.txt`
+ presets, the crypto dependency for the file backend, and the `Secret`/`SecureString` type that
enforces the zeroize/redact/constant-time invariants above.
