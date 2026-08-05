# keyward — design & roadmap

## What keyward is

A **schema-driven, OS-backed credential SDK** with a small TUI front-end — a
thin facade over the operating system's own credential manager, in the same
category as Python `keyring`, Node `keytar`, and the Rust `keyring` crate (all
production-trusted).

keyward is **not** a vault competing with Keychain / libsecret / Credential
Manager. At-rest security is **delegated** to those audited OS stores. keyward
owns:

- **correct integration** with each OS store,
- a **flexible credential schema** (declare a record's fields once),
- **access control** (an authenticator layer, later),
- **not leaking secrets** while they pass through your process.

The practical consequence: the OS-backed path needs **no full cryptographic
audit** — the trust anchor is the OS store. The portable encrypted-file backend
(for headless/CI where no OS store exists) uses audited primitives (Monocypher
today; a libsodium hardening pass later).

## Developer experience

Declare a credential type as a struct plus a `schema()` listing its fields. The
schema is the **single source of truth**.

```cpp
struct FredCredential {
  std::string api_key;
  static keyward::Schema<FredCredential> schema() {
    return {{"api_key", &FredCredential::api_key, keyward::Sensitive}};
  }
};

struct JiraCredential {
  std::string email, url, token;
  static keyward::Schema<JiraCredential> schema() {
    return {{"email", &JiraCredential::email},                     // plain
            {"url",   &JiraCredential::url},                       // plain
            {"token", &JiraCredential::token, keyward::Sensitive}}; // masked + secret
  }
};
```

That one schema drives three things:

1. **the TUI** — what fields to prompt for, and which to mask;
2. **storage** — how the record serializes into **one opaque item** in the OS
   credential manager (one save / one unlock per credential);
3. **typed access** — the app reads `jira.token`, not `record["token"]`.

Add a field and the TUI, the storage, and the typed access all follow.

## API

```cpp
keyward::Vault vault{"myapp"};              // app identity = the namespace

vault.has("jira");                          // -> bool
vault.save("jira", JiraCredential{...});    // serialize -> one OS cred item
vault.load<JiraCredential>("jira");         // OS cred item -> typed record
vault.remove("jira");

// load-or-(prompt-then-save), in one call:
auto jira = vault.ensure<JiraCredential>("jira", prompter);
```

keyward stays **TUI-agnostic**. It talks to a `Prompter` interface; the TUI
*implements* it, so the SDK never depends on the TUI and tests use a fake
prompter.

```cpp
struct Prompter {
  virtual bool collect(std::string_view service, keyward::Fields& inout) = 0;  // false = cancel
  virtual ~Prompter() = default;
};
```

App flow: `ensure` fires the TUI **only when the credential is absent**; after
that, functions read the typed fields directly for their auth calls.

## Layering

```
Vault<T>       typed record <-> Fields, via the schema (member pointers)
   |           encode/decode a record  <-- the record codec
   v
SecretStore    dumb key -> bytes:  env var -> OS keychain -> encrypted file
   v
Keychain / libsecret / Credential Manager / seal-unseal
```

The TUI is a **separate thin consumer app** (FTXUI), not part of the library.

## Trust — two bars

- **Bar A — your own keys, at rest, your machine.** Close: finish the record
  layer + a libsodium in-process hardening pass.
- **Bar B — a general SDK others trust with real users' secrets.** The OS
  delegation removes the crypto-audit gate. What remains is *integration
  correctness*, *in-process handling*, and the *agent/authenticator* — the one
  surface that introduces new attack surface and warrants a focused review.

Current weakest link: secrets held in a plain `std::string` can reach swap or a
core dump. The libsodium pass (secure memory, `randombytes_buf`, `sodium_memcmp`)
closes it.

## Roadmap

Built and merged: `Secret` (zeroizing, constant-time compare); `seal`/`unseal`
(Argon2id + XChaCha20-Poly1305, Monocypher); `SecretStore` + macOS Keychain +
file + fallback tiers.

Next, in order:

1. **Record codec** — serialize a record's fields to bytes and safely back
   (length-prefixed, bounds-checked parse).
2. **Typed `Schema` / `Vault`** facade over `SecretStore`.
3. **Format version byte** — so the on-disk/on-item format can evolve.
4. **libsodium hardening pass** — secure memory for `Secret`, OS CSPRNG,
   constant-time compare.
5. **Linux libsecret + Windows Credential Manager** backends.
6. **Threat-model doc + fuzzing** the parse paths.

Deferred / review-gated: **authenticator → agent** (biometric / passphrase /
TTL, then an ssh-agent-style local daemon). Alongside: install/export packaging
and the TUI app.

**Compatibility north star:** a secret written by Python `keyring` is readable
by keyward and vice versa, green on all three OSes.
