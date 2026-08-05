# Task 3 — Encrypted secret blob (`seal` / `unseal`)

**Goal.** Turn a passphrase and a plaintext secret into a self-contained
encrypted blob, and back again — the crypto core the encrypted-file backend
will store. This is the load-bearing piece: you write it.

## The contract

Implement these two in `src/secret_box.cpp` (declared in
`include/keyward/secret_box.hpp`):

```cpp
std::string seal(std::string_view plaintext, std::string_view passphrase);
std::optional<std::string> unseal(std::string_view blob, std::string_view passphrase);
```

- `seal` returns a **fresh blob every call** — it carries its own random salt
  and nonce, so two seals of the same input differ.
- `unseal` returns the plaintext, or **`std::nullopt`** if the passphrase is
  wrong, the blob was tampered with, or it is malformed/truncated. Wrong input
  is a `nullopt`, **never** an exception and **never** an out-of-bounds read.

## What's provided (plumbing — don't rewrite)

- **`keyward::random_bytes(n)`** (`keyward/random.hpp`) — fresh random bytes for
  your salt and nonce.
- **Monocypher 4.0.2**, vendored at `third_party/monocypher/`. `#include
  "monocypher.h"` in your `.cpp`. It's already on the library's private include
  path and compiled in.
- The oracle tests (`tests/secret_box_test.cpp`) and the CMake wiring.

## The recipe

Passphrases are low-entropy, so you can't use one as a key directly. Two steps:

1. **Stretch** the passphrase into a 32-byte key with **Argon2** (`crypto_argon2`),
   using a random 16-byte **salt**.
2. **Encrypt + authenticate** the plaintext with **XChaCha20-Poly1305**
   (`crypto_aead_lock`), using that key and a random 24-byte **nonce**. It
   produces the ciphertext plus a 16-byte **MAC** (authentication tag).

`unseal` reverses it: read the salt + nonce from the blob, re-derive the key
from the passphrase, then `crypto_aead_unlock` — which returns non-zero if the
MAC doesn't match (wrong passphrase *or* tampering), your `nullopt` signal.

### Suggested blob layout

```
[ salt(16) | nonce(24) | mac(16) | ciphertext(N) ]
```

Fixed-size fields first makes parsing trivial — and gives you the length check
`unseal` needs: anything shorter than `16 + 24 + 16 = 56` bytes is malformed,
return `nullopt` before you touch it.

### Monocypher API you'll use

```c
void crypto_argon2(uint8_t *hash, uint32_t hash_size, void *work_area,
                   crypto_argon2_config config,       // {algorithm, nb_blocks, nb_passes, nb_lanes}
                   crypto_argon2_inputs inputs,        // {pass, salt, pass_size, salt_size}
                   crypto_argon2_extras extras);       // crypto_argon2_no_extras
void crypto_aead_lock  (uint8_t *cipher, uint8_t mac[16], const uint8_t key[32],
                        const uint8_t nonce[24], const uint8_t *ad, size_t ad_size,
                        const uint8_t *plain,  size_t text_size);
int  crypto_aead_unlock(uint8_t *plain,  const uint8_t mac[16], const uint8_t key[32],
                        const uint8_t nonce[24], const uint8_t *ad, size_t ad_size,
                        const uint8_t *cipher, size_t text_size);  // 0 = ok, -1 = forgery
void crypto_wipe(void *secret, size_t size);
```

Suggested Argon2 params: `algorithm = CRYPTO_ARGON2_ID`, `nb_passes = 3`,
`nb_lanes = 1`, `nb_blocks = 100000` (~100 MB). No additional data/key →
`crypto_argon2_no_extras`. The `work_area` is `1024 * nb_blocks` bytes you
allocate (e.g. a `std::vector<uint8_t>`) and `crypto_wipe` + free afterwards.

## Rules

- **Don't edit the tests** to pass. Make the code satisfy them.
- **Wipe key material.** The derived 32-byte key and the Argon2 work area are
  secrets — `crypto_wipe` them before they go out of scope. (`std::string`'s
  own buffer you can leave to a later hardening pass; the raw key you control
  here, so wipe it.)
- **Bounds-check on parse.** `unseal` gets attacker-controlled bytes. Validate
  the length first; never index past the end. ASan will catch you if you slip.
- Same interfaces stay put — a later harden pass may swap Monocypher/`random_bytes`
  for libsodium behind them, so keep the crypto self-contained in this file.

## Verify

```sh
cmake --preset debug && cmake --build --preset debug
ctest --preset debug --output-on-failure -R SecretBox      # 6 tests

cmake --preset asan  && cmake --build --preset asan
ctest --preset asan  --output-on-failure -R SecretBox      # bounds + leaks
```

**Done** = all 6 `SecretBox` tests green on both `debug` and `asan`, and
`clang-format` clean.
