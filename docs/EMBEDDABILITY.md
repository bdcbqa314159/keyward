# keyward — making it safe to embed (scope, not an implementation)

keyward is *"a lib that other people could use if they want to ship it in their
apps or bindings"* — and, stated alongside it as a **major requirement**, keyward
provides *everything needed*, including the CLI and GUI an app pulls into itself.
That answer, given 2026-08-20, changes what the next work should be. Five problems
stand between the current code and that goal, and all five outrank the open
questions in `FILE_ENCRYPTION.md` and `AGENT_SCOPE.md`.

Nothing here is implemented. Each item states what was measured, why it matters
*specifically* for an embedded library, and what the fix costs.

## The shift in posture

Everything so far was built for a consumer who owns their whole build. An
embedded library is the opposite: it shares a process, a link line and a symbol
table with code it has never seen. Three rules follow, and they explain most of
what is below.

1. **You do not own the process.** No process-global state, no prompting, no
   spawning daemons. (This already correctly killed `PR_SET_DUMPABLE` for the
   library, and it retires most of `AGENT_SCOPE.md`.)
2. **You do not own the link line.** Anything you bring, the host may already
   have — at a different version.
3. **Your headers are a contract.** Their *shape* cannot depend on how you were
   built.

## Problem 0 — the UI components are not actually shippable

**Stated requirement (2026-08-20):** keyward provides *everything needed* — if an
app wants a CLI or a GUI for its secrets, keyward supplies it rather than making
the app build one. That is a headline feature, not a nicety, which makes the
current state a contradiction:

- `keyward_tui` is **not installed at all**. The install set is
  `keyward keyward_cli monocypher sodium`; the prefix contains no TUI.
- `KEYWARD_BUILD_TUI` defaults to `PROJECT_IS_TOP_LEVEL`, so a **FetchContent
  consumer does not get the TUI by default** either. It exists for us, not for them.
- `keyward_tui` links `ftxui::component/dom/screen`, which are FetchContent
  targets. `FTXUI_ENABLE_INSTALL` is now `OFF` (set while stopping FTXUI polluting
  our prefix — right for hygiene), so an installed `keyward_tui` would have
  dependencies that do not exist on the target machine.

So today the CLI ships and the GUI does not. Fixing it needs three decisions,
because "ship a TUI inside someone else's app" is harder than shipping a library:

**Who owns the terminal?** `TuiPrompter` runs an FTXUI event loop. Inside a host
application that already owns the terminal — or is a GUI app with no TTY at all —
that is not a detail. The prompter needs a documented contract: what it does to
terminal state, whether it restores it, what happens with no TTY, and whether it
is safe to call from a thread that is not the host's main loop.

**How does FTXUI reach the user's machine?** Either vendor and hide it (same
problem as libsodium, one more dependency), require it as a system package, or
keep the TUI as a source-drop-in the app compiles itself. The third is unusual but
fits "we provide everything needed" without imposing our dependency graph.

**What does a GUI toolkit that is not FTXUI do?** An app built on Qt or GTK cannot
use an FTXUI prompter at all. The `Prompter` interface is the right seam — it is
already abstract — so the honest framing is: keyward ships *reference* prompters
(CLI, TUI) and any app can supply its own. That should be stated, because
"everything needed" otherwise implies a Qt prompter exists.

This is Problem 0 because it is a stated requirement that is currently unmet, and
because the answer to "how does FTXUI ship" is the same class of question as
Problem 1 (what we vendor and how we hide it) — they should be decided together.

## Problem 1 — 113 global symbols that can collide (highest risk)

Measured on the installed prefix:

- `libsodium.a` — **69** global `sodium_*` / `crypto_aead*` symbols
- `libmonocypher.a` — **44** global `crypto_*` symbols

keyward is static, so a host links all three archives. A host that also uses
libsodium (common) or Monocypher now has two definitions of `sodium_malloc`,
`crypto_aead_lock` and friends. The benign outcome is a duplicate-symbol link
error. The malign one is that the linker silently picks one, and keyward's calls
land in a **different version** of the primitive it was compiled against — an ODR
violation in the crypto layer, which is the worst place to have one.

Note this got *sharper* with the libsodium fix: keyward now depends on libsodium
being built with specific feature macros. Binding against a host's differently
configured libsodium would silently restore the fallback allocator — the exact
bug that shipped unnoticed before.

Options:

**A. Link a system libsodium instead of vendoring** (`libsodium-dev` /
`libsodium-devel` / `libsodium`). Removes our copy entirely; the host and keyward
share one. Cost: a hard external dependency, a version floor, and loss of control
over the feature macros — which is precisely what was just fixed. Also does
nothing for Monocypher.

**B. Hide the symbols.** Build the deps as objects inside keyward and localise
them (`-fvisibility=hidden` for a shared build; `objcopy --localize-symbol` or a
linker version script for a static one). The host's copy and ours stop seeing each
other. Cost: platform-specific plumbing, and static-library symbol hiding is
genuinely fiddly.

**C. Rename them.** Monocypher is vendored and small — 56 public declarations —
so a `keyward_` prefix is mechanical. libsodium is not ours and has no prefix
option in the wrapper.

**D. Ship shared-only and control exports** so only `keyward_*` / keyward C++
symbols are visible. Solves it cleanly, but presumes Problem 3 is done.

**Recommendation: D for the shared build, B for the static one, and C for
Monocypher regardless** — Monocypher is cheap to rename and removes a whole class
of collision for 44 symbols. Whether to keep vendoring libsodium at all is the
one genuine decision here.

## Problem 2 — headers whose shape depends on the build

`secret_service_store.hpp` and `polkit_authenticator.hpp` gate their **class
declarations** on build-config macros:

```cpp
#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)
class SecretServiceStore : public SecretStore { ... };
#endif
```

Those macros are `PUBLIC`, so a consumer sees the class only if *their* compile
also defines it. That is fine when one build system owns everything, and wrong
for a shipped library: an app or binding compiled with different flags sees a
different API, and the failure is a confusing "no such type" rather than an
honest error.

Fix: **always declare the classes; move the conditionality into the
implementation.** A `SecretServiceStore` on a build without libsecret should
construct and report `Unavailable`/throw a clear "not built with libsecret"
error. `polkit_available()` already models this well — a runtime query, not a
compile-time one. This also makes `KEYWARD_HAVE_*` private again, which is where
build config belongs.

Cost: small and mechanical. Do it before anything binds to these headers.

## Problem 3 — no shared-library story

No `BUILD_SHARED_LIBS` handling, no `CXX_VISIBILITY_PRESET`, no `SOVERSION`.
Bindings almost always want a `.so`/`.dylib`/`.dll`, and a shared build is also
the cleanest answer to Problem 1.

Needs: visibility default `hidden` plus an explicit export macro, an `SOVERSION`
policy, and a decision about whether the C++ API is exported at all from the
shared object (see below) or only the C ABI.

## Problem 4 — nothing bindable

There is **no `extern "C"` anywhere**. The API is C++ templates:

- `vault.hpp` — 6 templates (`save<T>`, `load<T>`, `ensure<T>`, `revise<T>`)
- `schema.hpp` — 4 templates
- 18 `throw` sites that must not cross a language boundary

Templates cannot be bound from Python, Rust, Go or anything else. But note **the
typed layer does not need to be bound.** It is sugar over a byte-oriented seam
that is already C-shaped:

```
Vault<T>   typed record  <-> Fields <-> bytes      <-- C++ only, stays C++
SecretStore   key -> bytes                          <-- this is what bindings want
```

A binding wants `get`/`set`/`remove`/`list` over `(service, name) -> bytes`, plus
the authenticator seam. Record encoding can happen in the binding's own language,
or via `encode_fields`/`decode_fields` exposed as C.

So a C ABI is a **thin** layer over `SecretStore` + the codec, not a mirror of the
whole API — with opaque handles, out-params for byte buffers, an explicit free,
and every one of the 18 throw sites converted to an error enum at the boundary
(`noexcept` on every C entry point, catch-all inside).

## Ordering, and why

0. **Problem 0's decisions**, at least the FTXUI one, since it shares an answer
   with Problem 1. Installing `keyward_tui` is otherwise a one-line change that
   ships something broken.
1. **Problem 2** (header stability). Smallest, purely mechanical, and everything
   else binds to these headers — doing it later means breaking consumers twice.
2. **Problem 1, Monocypher part** (rename to `keyward_*`). Mechanical, removes 44
   collidable symbols, independent of everything else.
3. **Problem 3** (shared build + visibility). Enables the clean answer to the rest
   of Problem 1.
4. **Problem 1, libsodium part.** Decide vendor-and-hide vs system dependency;
   this is the one real decision.
5. **Problem 4** (C ABI). Last, because it should be designed against a stable
   header set and a working shared build.

`FILE_ENCRYPTION.md`'s `KeyProvider` should be designed **after** step 5, since it
has to cross the C boundary — designing it first would be guessing at the
boundary's shape.

## Open questions

1. **Keep vendoring libsodium, or require a system one?** Vendoring keeps control
   of the feature macros that were silently wrong until recently; a system
   dependency avoids shipping 69 collidable symbols. This is the decision the
   rest hangs on.
2. Does the shared object export the **C++ API at all**, or only the C ABI? Only-C
   is far easier to keep stable, but forces C++ users through a lossy interface.
3. How does the TUI ship — vendor FTXUI and hide it, require it as a system
   package, or offer the prompter as source the app compiles? And does
   "everything needed" extend to a Qt/GTK prompter, or is the promise "reference
   prompters plus a seam for your own"?
4. Which bindings actually matter first — Python (where `keyring` interop already
   works and may make bindings less necessary), or something else?
5. `THREAT_MODEL.md` says *"not independently audited — do not entrust other
   people's high-value secrets."* In a library others ship, their users inherit
   that without reading it. Does it stay as-is, move to the README, or does the
   gap get closed before 1.0?
