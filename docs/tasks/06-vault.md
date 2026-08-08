# Task 6 — The `Vault` facade (`save<T>` / `load<T>`)

**Goal.** The public API a consumer actually calls. `Vault` ties together the two
layers you already built — the schema mapping (`struct ⇄ Fields`) and the record
codec (`Fields ⇄ bytes`) — and parks the result in the underlying `SecretStore`
(OS keychain, or the file fallback). After this task, another project can declare
a credential type and `save`/`load` it. That's the "pluggable" milestone.

## The contract

Implement the two template methods in `include/keyward/vault.hpp` (the rest —
constructors, `has`, `remove` — is done for you):

```cpp
template <class T> void save(const std::string& service, const T& record);
template <class T> std::optional<T> load(const std::string& service);
```

- `save` — turn `record` into bytes and store them under `service`.
- `load` — fetch `service`, turn the bytes back into a `T`; **`std::nullopt`** if
  the service isn't present *or* the stored bytes don't parse into a `T`.

## This task is composition — you already wrote every piece

You're not writing new logic, you're **chaining** the functions from tasks 4 & 5.
Walk the data down through the layers and back up:

```
save:   T  --to_fields-->  Fields  --encode_fields-->  std::string  --store_->set-->  backend
load:   backend  --store_->get-->  optional<string>  --decode_fields-->  optional<Fields>  --from_fields<T>-->  optional<T>
```

`store_` is the member (a `std::unique_ptr<SecretStore>`); call it with
`store_->get(service)` / `store_->set(service, blob)`.

### `save` — the straight-through direction

```
Fields  f    = to_fields(record);
std::string  blob = encode_fields(f);
store_->set(service, blob);
```

(You can inline it to fewer lines once you see the shape.)

### `load` — the direction with two ways to fail

Each step down can come back empty, and you must **stop at the first miss** and
return `std::nullopt`. This is the same "short-circuit on failure" discipline as
`unseal`/`decode_fields`, now three links long:

```
1. auto stored = store_->get(service);      // optional<string>
   if (!stored) return std::nullopt;         // nothing stored under this service

2. auto fields = decode_fields(*stored);     // optional<Fields>
   if (!fields) return std::nullopt;          // stored bytes are corrupt / not ours

3. return from_fields<T>(*fields);            // optional<T> — already nullopt if a field is missing
```

Note step 3 already returns an `optional<T>`, so you can hand its result straight
back — `from_fields` does the "is this really a T?" check for you.

## Why `save`/`load` are templates but `has`/`remove` aren't

`save`/`load` need to know the record type `T` (to run *its* `schema()`), so they
must be templates and live in the header. `has`/`remove` only deal in the
`service` name and opaque bytes — no type involved — so they're plain methods,
already implemented.

## Rules

- **Don't edit the tests.** They inject an in-memory store, so nothing here
  touches your real keychain.
- `load` returns `std::nullopt` on *either* failure (absent, or unparseable) —
  never throws, never returns a half-built `T`.

## Verify

```sh
cmake --build --preset debug && ctest --preset debug -R Vault --output-on-failure
cmake --preset asan && cmake --build --preset asan && ctest --preset asan -R Vault
```

**Done** = all 6 `Vault` tests green on **debug** and **asan**, clang-format clean.
