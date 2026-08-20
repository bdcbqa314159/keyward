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

## Problem 0 — the contract is under-specified, and its reference UI does not ship

**What was actually asked for (2026-08-20):** keyward provides *"the contract that
has to be respected to use the library correctly"*. The TUI is one hands-on
realisation of that contract — and not an arbitrary one: **keyward was extracted
from an FTXUI application**, whose need for secrets is why this library exists. So
the promise is not "we ship a Qt app". It is: the contract is specified well
enough that a CLI, a TUI, or somebody's Qt app can each implement it correctly,
with our CLI and TUI as the worked proof.

That reframes the work. Shipping more UIs is not the deliverable; **a contract an
outsider can implement without reading our source** is.

### The contract is written in the wrong place

`Authorization` has four values, and the difference between two of them is
load-bearing: `FallbackAuthenticator` degrades on **`Unavailable` only**, so an
authenticator that returns `Denied` when it means "I could not ask" silently
strands the user with no fallback tier. That rule is documented in
`fallback_authenticator.hpp` — a file an implementer has no reason to open.
`authenticator.hpp`, which they *will* open, says only:

> `service` is the record being accessed; `reason` is a human-readable verb.
> Return Allowed to release the secret.

Nothing there would stop a third party writing the exact bug that
`PolkitAuthenticator` had to be carefully designed to avoid.

`Prompter` is better — it says a gatherer never touches storage or crypto — but
its obligations are still implicit. An implementer cannot tell from the header
whether they must preserve the field count and order, leave `value` untouched when
returning false, actually mask `sensitive` fields, avoid persisting or logging
what they collect, what to do with no TTY, or whether `collect` may throw.

### The contract is non-negotiable — which makes the conformance suite the point

**Decided 2026-08-20:** integrating teams implement the prompt window to
keyward's specification, not to their own taste. keyward runs a small prompt that
asks for exactly the fields the record's schema declares, with the sensitive ones
marked. The host conforms; the contract does not bend.

That is a defensible stance, and it has one consequence that cannot be skipped:
**"as we restricted it" is only meaningful if it is written down and checkable.**
Today it is neither — the load-bearing obligations live in the wrong file or only
in our implementations' comments, and there is no way for an integrating team to
verify their window conforms before shipping it. A non-negotiable contract with no
specification and no conformance suite is just an expectation.

### What "everything needed" should mean

> **Items 1 and 2 done (2026-08-20).** The obligations are now stated in
> `prompter.hpp` and `authenticator.hpp`, and `keyward/testing/conformance.hpp`
> ships as a framework-agnostic suite an integrating team runs against their own
> window. Writing the contract down also surfaced a real bug: `prompt_and_save`
> returned on cancellation *before* its wipe, so a passphrase typed and then
> backed out of was never zeroed. Item 3 — shipping the TUI — remains open.

1. **State the obligations where they are read** — in `authenticator.hpp` and
   `prompter.hpp`, as requirements on the implementer, not descriptions of our
   implementations.
2. **Ship a conformance suite.** There is none today: contract tests exist but are
   hard-wired to our own types. A header a third party instantiates against *their*
   `Prompter` / `Authenticator` / `SecretStore` turns "respect the contract" from a
   request into something they can run. This matters most for bindings, where the
   author cannot read C++ semantics out of our headers at all.
3. **Keep CLI and TUI as reference implementations** — and actually ship them,
   which today the TUI does not do (below).


### The examples are the acceptance test, and one of them fails today

**The bar (2026-08-20):** a CLI integration must be implementable *in minutes*
given how smooth the library is — and the same for other frameworks. That is the
point of the library, so it is the point of the examples. Three were named:
**CLI**, **FTXUI** (the founding use case), and **a GUI such as ImGui**.

Graded against that bar, using what the code actually does:

| Example | Minutes today? | Why |
|---|---|---|
| CLI | **yes** | `collect()` blocks; a terminal read blocks. The shapes match. |
| FTXUI | **only if the app cedes the terminal** | `TuiPrompter` satisfies `collect()` by running `screen.Loop(renderer)` — a *nested* event loop. An app that already owns a `ScreenInteractive` loop cannot host a second one. |
| ImGui | **no** | Immediate mode renders one frame per iteration and **cannot block**. There is no way to implement `bool collect()` in an ImGui app without pumping a nested render loop (invasive, framework-specific) or blocking a worker thread while the UI thread draws — which needs threading guarantees the contract does not make. |

So the ImGui example is not a nice-to-have: it is the case that **proves the
contract is the wrong shape** for a whole class of hosts. Immediate-mode GUIs,
event-driven apps and anything with a main loop it owns all hit the same wall.
Writing it is how that gets discovered concretely rather than argued about.

### The fix is small, because the code is already split

`Vault::prompt_and_save` does two separable things: it **builds** a
`std::vector<PromptField>` from `T::schema()`, then it **consumes** a filled one.
Only the middle line calls `collect()`. Exposing those two halves gives an
**app-driven** path alongside the blocking one:

- the app asks keyward which fields a record needs (name, sensitivity, prefill);
- the app renders them however it likes, across as many frames as it likes;
- the app hands the filled values back and keyward saves them.

That is a natural fit for ImGui and costs no expressiveness for the others —
`Prompter` stays exactly as it is for CLI and standalone-TUI hosts, which is where
blocking is the *right* answer. Both paths share the wiping and `from_fields`
logic that already exists.

**Recommendation: write the ImGui example first** — it is the one that fails, so
it is the one that tells us whether the app-driven path is needed and what shape
it wants.

**Deferred (2026-08-20).** ImGui and the app-driven path are parked until a
development round closes on Windows and macOS. Recorded here so the reasoning is
not rediscovered: the blocking `bool collect()` shape is a known limitation for
immediate-mode and main-loop-owning hosts, the fix looks like a small split of
`prompt_and_save`, and this analysis is **reasoned from ImGui's programming
model, not measured against a build** — treat it as a strong hypothesis, not a
finding, until the example exists.

### The TUI genuinely does not ship

- `keyward_tui` is **not installed at all**. The install set is
  `keyward keyward_cli monocypher sodium`.
- `KEYWARD_BUILD_TUI` defaults to `PROJECT_IS_TOP_LEVEL`, so a FetchContent
  consumer does not get it by default either — it exists for us, not for them.
- `keyward_tui` links FTXUI targets, and `FTXUI_ENABLE_INSTALL` is now `OFF` (set
  while stopping FTXUI polluting our prefix — right for hygiene), so an installed
  `keyward_tui` would have dependencies that are not there.

Installing it is a one-line change that would ship something broken. Two questions
first, and the second shares its answer with Problem 1:

**Who owns the terminal?** `TuiPrompter` runs an FTXUI event loop inside a host
that may already own the terminal, or be a GUI app with no TTY. Terminal state,
restoration, no-TTY behaviour and main-loop safety belong in the contract — this
is the sharpest case of "you do not own the process".

**How does FTXUI reach the user's machine?** Vendor and hide it, require it as a
system package, or ship the prompter as source the app compiles. Same class of
decision as libsodium, so decide them together.

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
3. ~~Does `Prompter` gain an app-driven path?~~ **Answered 2026-08-20: no — the
   contract is non-negotiable and hosts conform to it.** An integrating team
   implements the prompt window *as keyward specifies it*: a small modal that
   collects whatever fields the record's schema declares. `Prompter` stays
   blocking. An immediate-mode host must therefore run a modal or block a worker;
   the app-driven path stays parked with the ImGui example, as a possible future
   accommodation rather than a requirement.
4. How does the TUI ship — vendor FTXUI and hide it, require it as a system
   package, or offer the prompter as source the app compiles?
   (The Qt/GTK question is **answered**: keyward ships the contract and reference
   prompters, not a prompter per toolkit.)
5. Which bindings actually matter first — Python (where `keyring` interop already
   works and may make bindings less necessary), or something else?
6. `THREAT_MODEL.md` says *"not independently audited — do not entrust other
   people's high-value secrets."* In a library others ship, their users inherit
   that without reading it. Does it stay as-is, move to the README, or does the
   gap get closed before 1.0?
