# Fuzz seed corpora

Hand-authored starting inputs, one directory per harness. They are **read-only
input**: pass a separate directory first so libFuzzer writes what it discovers
there instead of growing these.

```sh
mkdir -p build/fuzz/found
./build/fuzz/fuzz_decode_fields build/fuzz/found tests/fuzz/corpus/decode_fields \
  -max_total_time=60
```

Regenerate them from `seal()` / `encode_fields()` rather than editing the bytes
by hand — several are real sealed blobs and a hand edit would just be noise the
fuzzer discards.

## `decode_fields/`
Valid encodings, so mutation starts from real structure instead of rediscovering
the length-prefix framing: empty, single field, a typical record, an embedded
NUL, an empty value, and a 1 KiB value. Worth roughly **55% more new coverage
units per minute** than starting from nothing (188 → 294 in a 20s run).

## `unseal/`
Real sealed blobs plus the two inputs that sit either side of the 56-byte header
boundary the parser keys on (`header_only`, `header_minus_one`).

At production KDF cost these seeds make throughput **collapse** — 12 executions
in 21 seconds, against ~17k/s for `decode_fields` — because every input past the
header pays a full Argon2id over a 100 MB work buffer. Fuzz builds therefore
compile a token Argon2 cost (`KEYWARD_FUZZ_CHEAP_KDF`, set only under
`KEYWARD_BUILD_FUZZERS`), which brings it to ~6.5k/s over the same branches.

One consequence to know: these blobs are sealed at *production* cost, so their
MAC will not verify in a fuzz build. The fuzzer covers parse-and-reject, not
parse-and-accept — which is what it would cover anyway, since no mutation gets
past a 128-bit MAC. The accept path is covered by `secret_box_tests` in a normal
build. See `docs/THREAT_MODEL.md`.
