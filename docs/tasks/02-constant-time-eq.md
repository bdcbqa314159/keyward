# Task 2 — constant-time compare (`Secret::equals`)

## Context
A credential SDK constantly compares a stored secret against a candidate — verifying an API
token, a session key, a password hash. The *obvious* way to compare (`==`, `memcmp`,
`std::equal`) is a **security bug**: it leaks the secret through timing. This task adds a
comparison that doesn't. It's yours to write (it's on the CLAUDE.local.md "my code" list).

## Background — the timing side channel
`memcmp`/`==`/`std::equal` **short-circuit**: they return the instant they find the first
differing byte. So the comparison takes *longer the more leading bytes match*. An attacker who
can measure response time can recover a secret **one byte at a time**:

> Guess the first byte 256 ways; the guess that makes the server take a hair longer matched. Lock
> it in, move to byte two. O(256·N) guesses instead of O(256^N) — a real, demonstrated attack on
> token/HMAC verification.

A **constant-time** compare removes the timing↔data correlation: it looks at **every** byte
regardless of where a mismatch is, accumulating the difference, and only decides at the end. The
canonical shape is "OR together the XOR of each byte pair, then test the accumulator against zero"
— crucially, **no `if (a[i] != b[i]) return …` inside the loop.**

## The flaw you're avoiding
There is no comparison on `Secret` yet — so the first person who needs one will reach for `==` and
introduce exactly this bug. You're providing the safe primitive so they never have to.

## Your task
Add to `keyward::Secret`:
```cpp
bool equals(std::string_view candidate) const noexcept;
```
Returns whether the secret's bytes equal `candidate`, comparing in a way whose running time does
**not** depend on *where* (or whether) the bytes differ.

**On length:** the *length* of a secret is generally treated as non-secret (libsodium requires
equal length; Python's `hmac.compare_digest` leaks length). So an early length check is acceptable
— the property that matters is that comparing **content** of equal-length inputs is constant-time.
Don't agonize over hiding length; do make the byte comparison branch-free on the data.

## Acceptance — the oracle
`tests/secret_eq_test.cpp` (wired as `secret_eq_tests`). Green = behaviour correct:
- identical bytes → `true`;
- same length, differ in first *or* last byte → `false`;
- different lengths (shorter/longer/empty candidate) → `false`;
- empty secret vs empty → `true`, vs non-empty → `false`.
```
cmake --build build/debug --target secret_eq_tests && ctest --test-dir build/debug -R SecretEquals --output-on-failure
```
The **timing property itself is not unit-testable** (timing tests are flaky) — it's verified by
**review + reasoning about your code**, same as zeroize in task 1. So the tests prove *correct*;
the review proves *constant-time*.

## Hints & research (pointers — not answers)
- **L1:** search *"constant time comparison"*, *"timing attack token compare"*, `CRYPTO_memcmp`,
  `sodium_memcmp`, Python `hmac.compare_digest` (read its docstring on what it does and doesn't hide).
- **L1:** the loop body accumulates, it never branches on the data — e.g. fold `a[i] ^ b[i]` into
  a running value with `|=`, then compare the accumulator to 0 *once*, at the end.
- **L1:** watch the compiler — a smart optimizer can turn a branchy version back into a short-circuit.
  A `volatile` accumulator (or the OS `*_memcmp`) is how libraries keep the property. (Stretch.)
- Say **"show me"** only after you've tried and are stuck.

## Constraints
- C++20, no new dependencies, honour the project's security invariants.
- No `if`/early-`return` that depends on a *content* byte inside the compare loop.
- Don't edit the tests to pass.

## Stretch (optional)
- A `volatile`-accumulator (or platform `*_memcmp`) version hardened against the optimizer.
- `bool equals(const Secret& other) const noexcept;` — compare two secrets.
- Reflect: should `Secret` have `operator==`? Why might exposing it be *worse* than a named `equals`?

## My working notes
<!-- scratch: what you tried, errors, questions -->
