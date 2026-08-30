# Platform-tail handoff briefs — round-2 remainder

The findings that the macOS review passes could not settle because they need real
**Windows** or **non-gnome Linux** behaviour to reproduce. Hand each section to an
agent (or reviewer) on the matching platform, in a fresh session started in this
repo. Full context: [SECURITY_AUDIT_2026-08.md](SECURITY_AUDIT_2026-08.md).

**Discipline (from the runbook): reproduce before fixing.** Each of these rests on
an assumption about undocumented or provider-specific behaviour. Confirm the
*actual* behaviour on real hardware first (a failing test / observed output), then
fix, then leave a regression test that fails before the fix. Two are marked
*Unverified* precisely because the bug may not exist as written — settle that
first and record a refutation if so.

---

## Windows agent

### M8 (Medium) — `remove()` TOCTOU on the bare `<app>` target
- **Location:** `src/windows_credential_store.cpp`, `remove()` (~:192-201) — a
  `readCredential` `UserName==name` check and `CredDeleteW` are two separate calls
  on a target namespace shared with Python `keyring`.
- **Reproduce (needs Windows + Python `keyring`):** keyward stores at a compound
  target, but `keyring` writes the "newest-for-service" secret at the *bare*
  `<app>` target. Between keyward's read-check and its `CredDeleteW`, run
  `keyring.set_password(app, other, ...)` so a *different* credential now occupies
  the bare target. `CredDeleteW` has no conditional-on-username form, so keyward
  deletes whatever is there now — destroying an unrelated credential. Confirm the
  window exists by observing the wrong credential deleted.
- **Fix direction:** re-read after the delete and restore / flag if a different
  `UserName` reappeared at the target, or don't delete the bare target at all and
  report it to the user. Pick based on what `keyring` interop actually needs.
- **Acceptance:** a regression test (host-gated, `KEYWARD_HOST_TESTS`) that seeds
  the race and shows the unrelated credential survives; runs green on
  `windows-latest`.

### U1 (Unverified) — `CredEnumerateW` leading-wildcard filter
- **Location:** `src/windows_credential_store.cpp`, `list()` (~:206-212) —
  `CredEnumerateW(L"*@<app>", 0, &n, &c)`.
- **Reproduce / settle (needs Windows):** the Win32 docs describe a *trailing*-only
  wildcard; a **leading** one is undocumented. CI (`windows-latest`) currently
  asserts `list()` returns both names, so the runtime accepts it — but this leans
  on undocumented behaviour that could regress to an *incomplete* list (the
  contract forbids that) or a throw. Run `CredEnumerateW(L"*@x", 0, &n, &c)`
  directly and confirm whether the leading wildcard is honoured across Windows
  versions.
- **Fix direction (if it doesn't hold):** enumerate with a documented filter (e.g.
  `NULL`/all + filter in code, or a trailing-wildcard scheme) so `list()` can never
  silently return a partial set. If it *does* hold reliably, record the evidence
  and downgrade U1 to a documented reliance.
- **Acceptance:** either a refutation with evidence, or a fix + a test that fails if
  enumeration returns a partial list.

---

## Linux agent

### M2 (Medium) — polkit maps an interactive refusal to `Unavailable` (downgrade)
- **Location:** `src/polkit_authenticator.cpp` (~:103-117, esp. :107 and :117).
- **Reproduce (needs a real polkit agent + desktop):** with
  `FallbackAuthenticator{Polkit, Passphrase}`, a *present* user who **cancels /
  declines** the polkit dialog. In common polkit versions this returns a *result*
  with `is_authorized=false, is_challenge=true` → line 117 `Unavailable` →
  `FallbackAuthenticator` runs the weaker passphrase tier. Also: the cancel guard
  at :107 matches only `G_IO_ERROR/G_IO_ERROR_CANCELLED`, but a dialog-cancel is
  usually surfaced in the polkit/D-Bus error domain
  (`org.freedesktop.PolicyKit1.Error.Cancelled`), which misses that match. **First
  establish empirically** what polkit actually returns on (a) dialog-cancel and (b)
  auth-failure — the whole finding depends on version-specific behaviour.
- **Fix direction:** distinguish "no auth agent registered" (probe agent presence,
  or only degrade when `allow_interaction_==false`) from "interaction ran and was
  declined"; broaden cancel detection to the polkit error domain; map a *declined
  interactive challenge* to `Denied`/`Cancelled`, never `Unavailable`.
- **Acceptance:** a test (host-gated) showing a declined interactive polkit prompt
  does **not** fall through to the passphrase tier; note the polkit version tested.

### U2 (Unverified) — locked-search assumption on non-gnome providers
- **Location:** `src/secret_service_store.cpp` — the `get()` search (~:137-146),
  the `remove()` survivor search (~:249-253), and `list()` (~:268). (Line numbers
  drift; anchor on the `secret_service_search_sync` calls and the "locked
  collection still answers searches" reasoning in the comments.)
- **Reproduce (needs KWallet or KeePassXC as the Secret Service provider):** the
  fail-closed logic assumes "a locked collection still answers attribute
  searches" — true for gnome-keyring (the only daemon CI tests). A provider that
  exposes **no collection while locked** yields `matched==0` → `get` returns
  `nullopt` → (historically) a downgrade. Run `tests/run_isolated_keyring.sh`
  against KWallet / KeePassXC and observe whether a locked search returns matches.
- **Fix direction (if the assumption breaks):** don't infer "absent" from
  `matched==0` on a provider that hides locked collections — detect the locked
  state another way (collection lock status via the Secret Service API) and fail
  closed rather than returning `nullopt`. If the assumption holds on these
  providers too, record the evidence and close U2.
- **Acceptance:** a refutation with evidence, or a fix + a locked-provider test.

---

## Not a platform-agent item — L7 is macOS (handle directly)

**L7 (Low)** lives in `src/biometric_authenticator.cpp` (~:38, :45-50):
`LAErrorBiometryLockout` and `LAErrorUserFallback` fall into `else → Denied`, which
does **not** fall through, so a locked-out user is stranded even with a passphrase
tier present (inverse error — over-denying; fails closed, not a bypass). Fix is a
one-line mapping to `Authorization::Unavailable` so the passphrase tier becomes
reachable — doable from a macOS session (this repo's host), not a platform agent.
Dynamic verification needs a real locked-out Touch ID sensor; the mapping change
itself is low-risk and mirrors the Windows default.
