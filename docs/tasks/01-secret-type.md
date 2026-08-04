# Task 1 — the `Secret` type

## Context
keyward stores and moves secrets, but right now every secret is a bare `std::string`: copyable,
printable, and left sitting in memory after use. Before any backend touches real credentials we
need a **secure value type** that makes the security invariants in `CLAUDE.md` *structural*, not
hopeful. It's the foundation the constant-time compare (task 2) and the encrypted-file backend
build on. **This is yours to write** — I've laid down the failing test; you make it green.

## Background — what a "secure string" is
A `Secret` / `SecureString` is a small RAII value that owns sensitive bytes and enforces, by
construction:
- **No accidental exposure.** It never prints or converts to its plaintext. Any textual form is
  redacted (`****`). No `operator<<`, no implicit `std::string` conversion.
- **Zeroization.** When it dies (or is moved-from) it overwrites its bytes so they don't linger in
  freed heap memory. A plain `std::string`'s destructor just frees — the bytes stay in the page
  until it's reused.
- **Move-only.** Copying a secret makes another copy to leak; forbid copies, allow moves.

(Constant-time comparison and no-swap `mlock` are related invariants — later tasks.)

## The flaw you're setting up to remove
`SecretStore::get` returns `std::optional<std::string>` — copyable, printable, non-zeroizing
plaintext. `Secret` is the type we'll migrate that surface onto once it exists.

## Your task
Create `include/keyward/secret.hpp` with a `keyward::Secret` satisfying the acceptance tests.
The public surface the tests assume (design the *internals* however you like; if you'd shape the
surface differently, say so and I'll re-pin the tests):

```cpp
explicit Secret(std::string bytes);        // takes ownership of the bytes
~Secret();                                 // zeroize the bytes before they're freed
Secret(Secret&&) noexcept;                 // move
Secret& operator=(Secret&&) noexcept;
Secret(const Secret&) = delete;            // no copies
Secret& operator=(const Secret&) = delete;
std::string_view view() const noexcept;    // borrow the bytes (caller must not persist them)
std::size_t     size() const noexcept;
bool            empty() const noexcept;
std::string     redacted() const;          // a masked form safe for logs — never the bytes
```
Header-only is fine (small type; no `.cpp` / CMake change needed).

## Acceptance — the oracle
`tests/secret_test.cpp` is wired as the **`secret_tests`** target. Green = done. It checks:
- **holds & borrows** — `view()` returns the bytes, `size()`/`empty()` agree;
- **redaction** — `redacted()` never contains the plaintext and isn't empty;
- **move-only** — `static_assert` (no copy, yes move), and a moved-from `Secret` is `empty()`.

```
cmake --preset debug && cmake --build build/debug && ctest --test-dir build/debug --output-on-failure
```
(Right now `secret_tests` fails to even compile — `keyward/secret.hpp` doesn't exist yet. That's
your red. Create the header, make it build, then make the assertions pass.)

Two invariants the tests can't easily prove — **checked in review + the `asan` build**, so do them:
- **zeroize-on-destroy** (and on move-from): overwrite the bytes, and stop the compiler optimizing
  the wipe away.
- **no path to the plaintext**: no `operator<<`, no implicit `std::string` conversion.

## Hints & research (pointers — not answers)
- **L1:** search *"C++ secure zero memory"*, *"memset before free optimized out"*, `explicit_bzero`,
  `SecureZeroMemory`, `std::fill` + `volatile`. cppreference: `std::string_view`, `= delete`,
  rule-of-five, `noexcept` move ops.
- **L1:** pick your own mask policy for `redacted()` — the test only requires "no plaintext, non-empty."
- Say **"show me"** only after you've tried and are stuck; then I show the minimal fix and we move on.

## Constraints
- C++20, header-only, no new dependencies. Honour the `CLAUDE.md` invariants & conventions
  (value semantics, `unique_ptr` not `shared_ptr`, interfaces clean).
- Don't edit the tests to pass — make `Secret` satisfy them.

## Stretch (optional)
- A compile-time check that `Secret` is *not* streamable / convertible (a concept / `requires`).
- A constructor that moves in from a mutable buffer and zeroizes the source.

## My working notes
<!-- scratch: what you tried, errors you hit, questions -->
