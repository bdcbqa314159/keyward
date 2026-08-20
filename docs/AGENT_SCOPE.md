# keyward — the agent (scope, not an implementation)

`AUTHENTICATOR.md` sketches a long-lived daemon and calls it *"the one genuinely
new attack surface in keyward"*. This document takes that seriously: it forces the
decisions the sketch leaves open, and argues for building less than was sketched.
Nothing here is implemented.

Everything else in keyward is a library that runs inside a caller's process and
holds a secret for microseconds. An agent is a **process that stays alive holding
authority**, reachable by other processes. That is a different kind of thing and
deserves a different level of scrutiny.

## Decision 1 — does the agent hold secrets, or only decisions?

This is the fork that determines everything else. The sketch says
`{allow|deny}` *"(+ optionally the secret)"*; that parenthesis is two different
products.

**A. Authorizer.** The agent answers "has the user approved access to `service`
recently?" and nothing more. Clients still read from the OS keyring themselves.
The agent holds a TTL table of approvals — no secret material at all.

**B. Secret holder** (ssh-agent's model). The agent unlocks the keyring once and
serves secrets to clients. Clients never touch the keyring.

|  | A. Authorizer | B. Secret holder |
|---|---|---|
| What a compromised agent leaks | which services were approved, and when | **every secret it holds** |
| Keyring interaction | every client, every read | once |
| Memory hygiene burden | negligible | high — long-lived plaintext |
| Buys on Linux | cross-process TTL for polkit prompts | avoids repeated keyring unlocks |

**Recommendation: A.** It delivers the actual user-visible win — not being
re-prompted in every process — for a fraction of the blast radius. B is what
makes an agent a high-value target, and keyward has no requirement yet that only
B satisfies. If B is ever wanted, it should be a separate, later decision made
against a written threat model, not an "optionally" in a protocol sketch.

## Decision 2 — be honest about what same-uid trust is worth

The sketch's Model A trusts any process running as the same user, reasoning that
"same-uid *is* the trust domain". That is true as far as it goes, but the agent
should not be described as an isolation boundary, because on Linux it is not one:

- Any same-uid process can attach to the agent with `ptrace` and read its memory.
  `/proc/sys/kernel/yama/ptrace_scope` is **1** on this machine, which restricts
  that to descendants — a real mitigation, but it is a tunable, not a guarantee,
  and `0` is still common.
- `/proc/<pid>/mem` is readable under the same rules.
- Anything that can talk to the socket can simply *ask*, and under Model A it will
  be answered.

So the agent's value is **enforcing user presence**, not preventing a same-uid
attacker from getting secrets. Under option A that gap is small, since the worst
a compromised peer learns is approval state. Under option B it is the whole
product, and Model B (verify the caller's code signature) becomes load-bearing
rather than "opt-in for high-assurance deployments" — another reason A is the
safer starting point.

`THREAT_MODEL.md` already places "malware running as the same user" out of scope.
An agent must not quietly imply otherwise.

## Decision 3 — what does this buy on Linux specifically?

The macOS rationale is concrete: an unsigned dev build changes identity on every
rebuild, so the Keychain re-prompts, and a stable code-signed agent fixes it.
**Linux has no equivalent nag** — gnome-keyring does not re-prompt per binary.

So on Linux the agent buys:

- one presence prompt shared across processes, rather than one per process
  (this is the real win, and only once `PolkitAuthenticator` is in use);
- a place to hold a TTL that survives a short-lived CLI invocation.

That is worth something, but it is worth *less* than on macOS, and it is worth
nothing at all to a user running with `NoAuth`. Worth stating plainly before
anyone builds a daemon for it.

## Decision 4 — lifecycle: on-demand spawn, or socket activation?

The sketch says "spawned on demand, idle-timeout shutdown". On-demand spawn from
inside a library has a race — two processes starting at once both try to become
the agent — and needs locking, stale-socket cleanup, and a story for what happens
when the binary is upgraded underneath a running agent.

Linux has a better answer: a **systemd user unit with socket activation**.
systemd owns the socket, starts the agent on first connection, applies the idle
timeout, and removes the spawn race entirely. It also gives sandboxing for free
and worth using — `ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`,
`MemoryDenyWriteExecute`.

The cost is a systemd dependency for the good path, so a portable fallback spawn
is still needed. **Recommendation: socket activation as the supported path on
Linux, with the manual spawn as a documented fallback rather than the default.**

## Decision 5 — the socket, and the protocol as attack surface

`$XDG_RUNTIME_DIR` is `/run/user/1000`, mode `0700`, owned by the user — a good
home for a `0600` socket. Requirements, none optional:

- Verify the peer with `SO_PEERCRED` and refuse a uid mismatch, rather than
  relying on directory permissions alone.
- Refuse to listen if the containing directory is not `0700` and user-owned.
- Handle a stale socket from a crashed agent without blindly unlinking one a live
  agent is using.

And the part that is easy to under-rate: **the protocol parser reads
attacker-controlled bytes from any same-uid process.** That puts it in the same
category as `decode_fields` and `unseal`, both of which are fuzzed in CI. So:
framed, versioned, hard length caps, bounded connection count, no secret material
in any error string — and **a libFuzzer harness from day one**, not later. The
harness pattern already exists in `tests/fuzz/`.

## Decision 6 — memory hygiene, which just got easier

If option B is ever chosen, the agent holds plaintext for its whole lifetime, and
memory hygiene stops being a detail. Two things now help:

- `Secret` really is guard-paged, `mlock`ed and `MADV_DONTDUMP`ed as of the
  libsodium fix — it silently was not before, which is exactly the sort of thing
  a long-lived secret holder cannot afford.
- **`prctl(PR_SET_DUMPABLE, 0)` finally fits.** It was rejected for the library
  because a library must not impose a process-global setting on its host. The
  agent *is* our process, so it can and should set it, along with a zero core
  limit.

Under option A neither is critical, which is a further argument for A.

## Testing strategy

A daemon is only as trustworthy as what can be tested about it headlessly:

- Socket-level integration tests against an agent started with a temporary
  `XDG_RUNTIME_DIR`, in the style of `tests/run_isolated_keyring.sh`.
- A fuzz harness over the protocol decoder, wired into the existing fuzz job.
- Explicit tests for the fail-closed paths: agent unreachable, malformed frame,
  uid mismatch, TTL expiry — each must deny, and `Cancelled` must stay
  distinguishable from `Unavailable`.
- The interactive grant path stays untestable in CI for the same reason
  `PolkitAuthenticator`'s does; say so rather than fake it.

## Phasing

`AUTHENTICATOR.md` puts a `CachingAuthenticator` (in-process TTL) at step 2, and
that is the right order — **most of the perceived benefit of an agent is actually
the TTL cache**, which needs no daemon at all. Build that, live with it, and see
whether cross-process sharing is still wanted before writing a line of daemon.

1. `CachingAuthenticator` (in-process TTL) — no new surface, most of the value.
2. Measure: is being re-prompted across processes actually a problem in practice?
3. Only then: agent, option A, socket-activated, fuzzed protocol.
4. Option B (secret holder) — separate decision, separate threat model, separate
   review.

## Open questions

1. Authorizer (A) or secret holder (B)? Recommendation: **A**, with B deferred.
2. Is an agent wanted on Linux at all, given the macOS rebuild-nag rationale does
   not apply here?
3. Socket activation as the supported path, with manual spawn as fallback?
4. What does the TTL key on — service alone, or service plus caller identity? The
   first means process B silently inherits process A's approval.
5. Does step 1 (`CachingAuthenticator`) plus measurement come before any daemon
   work is scheduled?
