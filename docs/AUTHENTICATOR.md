# keyward — authenticator design (draft)

The **authenticator** is an *access-time* gate: before a stored secret is handed
back to the app, prove the user authorizes it. The OS keychain protects secrets
*at rest*; the authenticator adds *"who is asking, right now, and do they mean
it?"* on top.

Status: **design only — not built.** This is the review-gated security layer;
the agent (below) is the one genuinely new attack surface in keyward, so it lands
last and warrants a focused review.

## Why it exists

1. **Silent access.** Once a process can read from the keychain, *any* code in
   it can pull a secret with no user interaction. A per-access gate (biometric /
   passphrase) forces user presence and intent.
2. **The macOS rebuild-nag.** An unsigned/rebuilt app changes code identity every
   build, so the Keychain re-prompts "allow access?" on each rebuild. A long-lived
   **code-signed agent** that owns keychain access has a *stable* identity — it
   authorizes once, and clients talk to it, ending the nag.

## Goals / non-goals

**Goals:** a pluggable gate (None / Passphrase / Biometric / Agent); TTL caching
(authorize once, reuse briefly); cross-platform; fail-closed.

**Non-goals:** it does **not** replace at-rest protection, and it does **not**
defend against a process that is *already* authorized (same boundary as
[THREAT_MODEL.md](THREAT_MODEL.md)) — once the app holds the plaintext, it's the
app's to protect.

## The interface

Errors are values (Result / `tl::expected`-style), never exceptions carrying
secret material.

```cpp
enum class Authorization { Allowed, Denied, Cancelled, Unavailable };

class Authenticator {
 public:
  virtual ~Authenticator() = default;
  // Prove the user authorizes access to `service` for a human-readable `reason`.
  // Only `Allowed` releases the secret; everything else fails closed.
  virtual Authorization authorize(std::string_view service, std::string_view reason) = 0;
};
```

Implementations:

| Backend | Behaviour |
|---|---|
| `NoAuth` | always `Allowed` — dev/CI only, **explicit opt-in** |
| `PassphraseAuth` | prompt via a `Prompter`, verify against a stored Argon2 verifier (constant-time) |
| `BiometricAuth` | Touch ID (macOS `LAContext`), Windows Hello (`UserConsentVerifier`), Linux → polkit or passphrase fallback |
| `AgentAuth` | delegate to the agent (which owns biometric + the cross-process TTL cache) |

## Where it plugs in

The gate lives at the **`Vault`** layer, not `SecretStore` — so policy is
per-typed-service and the store stays a dumb `key→bytes` sink:

```
Vault::load<T>(service):
    if (authenticator.authorize(service, "read") != Allowed) return nullopt;
    ... existing load ...
```

An unauthenticated `Vault` uses `NoAuth` (today's behaviour), so this is additive.

## TTL caching

Authorizing on *every* call is unusable. After a success, cache
`service → expiry` for a configurable TTL (default ~5 min):

- within the window, `authorize` returns `Allowed` without prompting;
- expiry, an explicit `lock()`, or (optionally) OS screen-lock clears it;
- the cache itself holds no secret — just authorization state — but lives in
  secure memory and is wiped on clear.

Per-process by default; the **agent** holds it cross-process.

## Trust model (for the agent)

- **Model A — trust same-uid local process (DEFAULT, ssh-agent style).** The
  agent serves any process running as the same user. Rationale: on a single-user
  machine same-uid *is* the trust domain, and the real boundary is the per-op
  biometric, not caller identity.
- **Model B — verify caller code-signature (opt-in).** Higher assurance, but it
  **reintroduces the rebuild-nag inside our own agent** (every rebuild changes
  identity) — so it's opt-in for high-assurance deployments only.

## The agent (optional, last)

> **Scoped in [AGENT_SCOPE.md](AGENT_SCOPE.md)** — which argues for building less
> than this section sketches. In short: make the agent an *authorizer* that holds
> approval state, not a *secret holder*; prefer systemd socket activation over
> on-demand spawn; treat the protocol as a fuzzed parser; and build the
> in-process `CachingAuthenticator` first, because most of the perceived benefit
> is the TTL cache rather than the daemon.

- Long-lived, **code-signed** daemon; owns keychain access (stable identity → no
  client rebuild-nag). Holds the biometric session + cross-process TTL cache.
- Transport: a **0600 unix domain socket** (`$XDG_RUNTIME_DIR/keyward-agent.sock`,
  or a per-user path); on Windows a **named pipe with a DACL**.
- Protocol: `{op: authorize|read, service}` → agent runs the authenticator →
  `{allow|deny}` (+ optionally the secret). Small, framed, versioned.
- Lifecycle: spawned on demand, idle-timeout shutdown.

## Fail-closed rules

Biometric unavailable, agent unreachable, user cancelled, protocol error → never
a silent `Allowed`. Distinguish `Cancelled` (user said no) from `Unavailable`
(couldn't ask) for UX, but both deny access.

## Phasing

1. `Authenticator` interface + `NoAuth` + `PassphraseAuth` (reuses the existing `Prompter`).
2. TTL-cache wrapper (`CachingAuthenticator`).
3. `BiometricAuth` — macOS Touch ID first, then Windows Hello.
4. `AgentAuth` + the agent daemon — **review-gated, last.**

## Open decisions (need a call before building)

1. **Gate granularity** — per-service (recommended), per-record, or a single
   global vault-unlock?
2. **Biometric policy** — required, or "biometric if available, else passphrase"?
   (Recommend the latter for portability.)
3. **TTL** — default value, and per-service vs global?
4. **Agent: build or defer?** (Recommend defer — it's the review-gated piece; the
   passphrase/biometric gate delivers most of the value without a daemon.)

## Security-review checklist (before the agent ships)

- Socket/pipe permissions (0600 / correct DACL, correct owner) and path safety.
- Framed, versioned, length-checked protocol; no injection/replay.
- No secret in logs, errors, or the protocol beyond the single release.
- TTL cache + any transient secret in secure memory; cleared on lock/exit.
- Caller trust model (A vs B) documented and enforced as configured.
