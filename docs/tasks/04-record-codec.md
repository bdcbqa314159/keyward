# Task 4 — Record codec (`encode_fields` / `decode_fields`)

**Goal.** Turn an ordered list of named fields into one self-contained blob, and
safely back. That blob is what a whole credential record becomes — the bytes
stored as a *single* item in the OS credential manager. It's the foundation the
typed `Vault` layer sits on.

Same muscle as `seal`/`unseal` (length-prefixed encoding + bounds-checked parse
of untrusted bytes), one level up: structured records now, not one secret.

## The contract

Implement these in `src/record_codec.cpp` (declared in `keyward/record.hpp`):

```cpp
struct Field { std::string name; std::string value; };
using Fields = std::vector<Field>;

std::string encode_fields(const Fields& fields);
std::optional<Fields> decode_fields(std::string_view blob);
```

- `encode_fields` → a blob that round-trips **exactly**, **preserves order**, and
  is **binary-safe**: names/values may contain any byte (`\0`, `=`, newline).
- `decode_fields` → the fields, or **`std::nullopt`** if the blob is truncated or
  malformed. Never an exception, and **never an out-of-bounds read** on hostile
  input.

---

## The concept

A credential is a list of `(name, value)` byte-strings. You need to pack them
into one string and unpack them later. The naive idea — `name=value\n` — breaks
the moment a token contains `=` or a newline. The fix is **length-prefixing**:
before each piece, write *how many bytes it is*, then the bytes. Now there's no
delimiter to collide with — the length tells you exactly where the piece ends.

### The concept, drawn as bytes

For `Fields{ {"url","x"}, {"k","ab"} }`, using a 4-byte length before each piece:

```
 00 00 00 03 | 75 72 6c | 00 00 00 01 | 78 | 00 00 00 01 | 6b | 00 00 00 02 | 61 62
 └ name_len ┘ └ "url" ┘ └ val_len ─┘ └"x"┘ └ name_len ─┘ └"k"┘ └ val_len ─┘ └"ab"┘
 └──────────── field 0 ─────────────────┘ └──────────── field 1 ────────────────┘
```

An empty `Fields{}` → an empty string (and must decode back to `{}`).

---

## Translating the concept into code

### Building block 1 — write a length (a number → 4 bytes)

A `uint32_t` is just 4 bytes. Write them out most-significant-first
("big-endian") so encode and decode agree regardless of machine:

```cpp
void put_u32(std::string& out, uint32_t n) {
  out.push_back(static_cast<char>((n >> 24) & 0xFF));  // top byte first
  out.push_back(static_cast<char>((n >> 16) & 0xFF));
  out.push_back(static_cast<char>((n >>  8) & 0xFF));
  out.push_back(static_cast<char>((n      ) & 0xFF));  // bottom byte last
}
```

### Building block 2 — read a length back (4 bytes → a number)

The mirror. Rebuild the number by shifting each byte back into place. Cast
through `unsigned char` first so a byte ≥ 0x80 doesn't sign-extend into garbage:

```cpp
uint32_t get_u32(std::string_view blob, std::size_t i) {  // caller has checked 4 bytes exist
  return (static_cast<uint32_t>(static_cast<unsigned char>(blob[i    ])) << 24) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 1])) << 16) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 2])) <<  8) |
         (static_cast<uint32_t>(static_cast<unsigned char>(blob[i + 3]))      );
}
```

### `encode_fields` — the easy direction

Walk the fields in order; for each, write `name` then `value`, each as
*length then bytes*. In concept:

```
for each field f:
    put_u32(out, f.name.size());   out += f.name
    put_u32(out, f.value.size());  out += f.value
```

`std::string::operator+=` / `append` copy raw bytes, so `\0` inside a value is
fine — you told it the length, it doesn't care what the bytes are.

### `decode_fields` — the direction that must be paranoid

Walk the blob with a **cursor** `i` (an offset). Each step: read a length, then
read that many bytes, advancing `i`. Before *every* read, check that many bytes
actually remain — the blob is attacker-controlled.

```cpp
std::optional<Fields> decode_fields(std::string_view blob) {
  Fields out;
  std::size_t i = 0;                       // cursor
  while (i < blob.size()) {
    // --- read the name ---
    if (blob.size() - i < 4) return std::nullopt;      // room for a length?
    uint32_t name_len = get_u32(blob, i);  i += 4;
    if (blob.size() - i < name_len) return std::nullopt; // room for the name?
    std::string name(blob.substr(i, name_len));  i += name_len;

    // --- read the value: same two checks ---
    // ... your turn ...

    out.push_back({std::move(name), /* value */});
  }
  return out;
}
```

The one idiom to internalize — the bounds check is written
`blob.size() - i < need`, **not** `i + need > blob.size()`. Why: `need` comes
from the attacker (it could be `0xFFFFFFFF`), so `i + need` can *overflow* and
wrap to a small number, sneaking past the check — then you read out of bounds.
Since `i <= blob.size()`, the subtraction on the left can't overflow, so it's the
safe form. This single detail is what the truncation / dropped-byte tests are
poking at.

Loop exits when `i == blob.size()` exactly → a clean, fully-consumed blob. If a
length ever points past the end, you already returned `nullopt`.

---

## Rules

- **Don't edit the tests** — make the code satisfy them.
- Every length is checked **before** it's used to read (the idiom above). asan
  will catch a miss.
- `put_u32` / `get_u32` are your helpers — put them in an anonymous namespace at
  the top of the `.cpp` (private to this file), like `u8` in `secret_box.cpp`.

## Verify

```sh
cmake --build --preset debug && ctest --preset debug -R RecordCodec --output-on-failure
cmake --preset asan && cmake --build --preset asan && ctest --preset asan -R RecordCodec
```

**Done** = all 7 `RecordCodec` tests green on **debug** and **asan**, and
clang-format clean.
