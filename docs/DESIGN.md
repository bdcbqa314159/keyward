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
- **access control** (the authenticator layer — passphrase / biometric / fallback),
- **not leaking secrets** while they pass through your process.

The practical consequence: the OS-backed path needs **no full cryptographic
audit** — the trust anchor is the OS store.

The portable file backend (for headless/CI where no OS store exists) was intended
to encrypt at rest with audited primitives, and `seal`/`unseal` (Argon2id +
XChaCha20-Poly1305, Monocypher) were built for it — but they were **never wired
in**, and the file store writes **plaintext** today. `FileSecretStore`'s own
header says so; this document previously did not. See
[FILE_ENCRYPTION.md](FILE_ENCRYPTION.md) for what closing that gap involves and
the decisions it is blocked on.

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
SecretStore    dumb key -> bytes:  env var -> OS keychain -> 0600 file (PLAINTEXT)
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

### Per-platform trust — the OS stores are not equivalent

Delegating at-rest security to the OS store means inheriting *its* threat model,
and the three differ in one dimension that matters:

- **macOS Keychain** ties each item to an **access-control list**: the creating
  app can restrict reads to itself, so another app running as the same user does
  **not** automatically get the secret.
- **Windows Credential Manager** has **no per-app isolation**. A generic
  credential is DPAPI-encrypted with a key bound to the user's logon, so it is
  protected against *other users* and *at-rest disk theft* — but **any process
  running in the same logon session can `CredRead` it**. keyward's namespacing
  (`keyward:<app>:<name>`) is organizational, not a security boundary.
- **Linux Secret Service** sits in between: the collection is unlocked per login
  session; isolation depends on the keyring daemon and desktop policy.

Practical guidance: on Windows, keyward defends against other users and a stolen
disk, **not** against malicious code already running as you. That is the same
guarantee as Python `keyring` / the Rust `keyring` crate on Windows — it is a
property of Credential Manager, not a keyward defect — but a secrets SDK should
state it plainly. The oversize blob limit (2560 bytes) is likewise a Credential
Manager property: keyward **fails closed** above it rather than downgrade to a
weaker store.

## Roadmap

**Shipped:** the record codec (versioned, bounds-checked); the typed
`Schema`/`Vault` facade; `Secret` on libsodium secure memory + constant-time
compare; native backends on **macOS Keychain, Windows Credential Manager, and
Linux Secret Service**; the **encrypted-file fallback** (Argon2id +
XChaCha20-Poly1305, opt-in via `KeyProvider` or `KEYWARD_PASSPHRASE`); CLI + TUI
prompters; the authenticator layer (passphrase / biometric / fallback); threat
model, fuzzing, ASan/UBSan/LSan CI, and install/`find_package`/pkg-config.

**Remaining:** the review-gated **agent daemon** (ssh-agent-style; see
[AUTHENTICATOR.md](AUTHENTICATOR.md) and [AGENT_SCOPE.md](AGENT_SCOPE.md)); a 1.0
freeze; and an **independent audit** (see [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)) —
the gate for entrusting others' high-value secrets. keyward is personal-grade
until then.

**Compatibility north star:** a secret written by Python `keyring` is readable
by keyward and vice versa, green on all three OSes.

Status: **Linux done** (`tests/secret_service_interop_test.cpp`, gated on the
pinned `keyring` in `.venv`). The Secret Service backend stores exactly the two
attributes `keyring` matches on — `service` (keyward's app namespace) and
`username` (the secret name) — and does not match the schema name, so items are
mutually visible. Reads, writes, cross-tool overwrite in both directions,
removal and `list()` are all covered.

The interop contract lives at the **`SecretStore`** layer: raw bytes under
(app, name). `Vault`'s typed `save<T>`/`load<T>` puts its own length-prefixed
record format *inside* that value, so a `keyring`-written plain password is a
readable secret but not a decodable keyward *record* — as intended.

**Duplicate items are a fact of this bus, not a bug we can avoid.** Secret
Service replaces an item only on an *exact* attribute-set match, and `keyring`
stores a third attribute (`application`) that we deliberately don't — so a
`keyring` write over a keyward item leaves two items, one stale. Consequences,
all covered by the interop test:

- `get` reads the most recently modified item, so the caller sees the current
  value rather than an arbitrary one.
- `modified` has **one-second** granularity. If the newest timestamp is tied
  between items holding *different* values, keyward cannot tell which is
  current and **throws** rather than risk returning a superseded secret —
  fail-closed, as the invariant requires.
- `set` clears before storing, so any keyward write collapses the duplicates.

macOS and Windows interop are unverified; `keyring` uses `SecItem` with
(service, account) there and a `service@username` target name on Windows, so
the mapping needs checking before either can be claimed.

**Which Secret Service providers are covered.** Only **gnome-keyring** is tested
— it is what CI runs and what the contract, interop and locked-keyring tests
exercise. Any spec-compliant provider (KWallet, KeePassXC with Secret Service
enabled) should serve keyward's *own* items, because they are stored and matched
by attributes we control.

Reading a provider's **native** entries is a different question and is out of
scope. KeePassXC surfaces its own database entries under its field names, not
ours — Python `keyring` carries a whole second attribute scheme for this
(`{service: "Title", username: "UserName"}` versus the default
`{service: "service", username: "username"}`). Supporting that would mean a
configurable attribute scheme; not worth building against a provider we have no
test coverage for, but the shape of the fix is known if someone asks for it.
