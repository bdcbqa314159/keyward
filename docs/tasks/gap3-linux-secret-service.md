# Gap 3 — the Linux Secret Service backend (libsecret)

Concept→code note for the delivered backend. Read this alongside
`src/secret_service_store.cpp`; it exists to make reading the code pay off rather than merging it
blind. Anything here you don't follow, flag it and we'll stop and deep-dive that specific thing.

## What this closes
keyward was consumable on macOS (real Keychain) and Windows (real Credential Manager). Linux fell
all the way through to the plaintext `0600` file — a real permission bit, unlike the Windows case,
but still plaintext at rest. Linux now gets its native OS vault.

That vault is the **freedesktop.org Secret Service API**: a D-Bus interface implemented by whichever
keyring daemon the user runs (gnome-keyring, KWallet, KeePassXC with Secret Service enabled). We
reach it through **libsecret**, the C client library. Same three-method shape as its siblings —
store / lookup / clear ↔ `CredWrite` / `CredRead` / `CredDelete` ↔ `SecItemAdd` /
`SecItemCopyMatching` / `SecItemDelete`.

## Build dependency — the one thing you must install
libsecret is **not** part of the OS, which makes this the only backend with a real external dep:

```sh
sudo apt install libsecret-1-dev libsecret-tools   # Ubuntu 26.04; tools gives you `secret-tool`
```

Reconfigure and you should see:
```
-- keyward: libsecret-1 0.21.7 found — Secret Service backend ON
```
Without it you get `libsecret-1 NOT found`, keyward still builds, and every Secret Service test
compiles to a skip. `secret-tool search application keyward:<app>` pokes the keyring by hand.

## Concept → code

### 1. The guard is two conditions, and that's the whole design constraint
```cpp
#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)
```
`__APPLE__` and `_WIN32` *prove* their APIs exist — Security.framework and Advapi32 ship with the
OS. `__linux__` proves nothing about libsecret. So CMake probes with pkg-config and defines
`KEYWARD_HAVE_LIBSECRET` only on success. The knock-on decisions:

- The define is **PUBLIC** in CMake, because the public header gates the *class declaration* on it —
  a consumer that compiled without it must not see a class that isn't there.
- The include dirs and link are **PRIVATE**, and `<libsecret/secret.h>` never appears in a public
  header. The dep stays an implementation detail.
- Includes are marked `SYSTEM` so glib's headers don't trip our `-Wall -Wextra -Wpedantic` (the same
  trick already used for FTXUI).

### 2. There is no key — identity is the attribute set
This is where it stops being a Windows lookalike. Windows has one `TargetName` string; the Keychain
has a `(service, account)` pair. Secret Service has neither: an item is `(attributes, secret)` where
attributes are a string→string dictionary, and a lookup is a **query for the item whose attributes
match**. We store two:

```cpp
constexpr const char* kAppAttr  = "application";   // "keyward:<app>"  — the namespace
constexpr const char* kNameAttr = "name";          // the caller's name
```

That falls out nicely for `list()`: search on the app attribute *alone* and every name in the
namespace comes back — a partial match, no prefix-stripping needed (contrast the Windows backend,
which enumerates `keyward:<app>:*` and then chops the prefix off each result).

The `SecretSchema` declares which attributes exist. Note how it's built:

```cpp
SecretSchema s{};        // value-init zeroes everything, including trailing reserved members
s.name = "com.keyward.Secret";
s.flags = SECRET_SCHEMA_NONE;
s.attributes[0] = {kAppAttr, SECRET_SCHEMA_ATTRIBUTE_STRING};
```
Imperative rather than brace-initialised on purpose: `SecretSchema` has reserved trailing members,
and naming only the fields we care about trips `-Wmissing-field-initializers` under `-Wextra`.
`SECRET_SCHEMA_NONE` (rather than `SECRET_SCHEMA_DONT_MATCH_NAME`) means lookups also match on the
schema *name*, so another program's coincidentally-similar attributes can't collide with ours.

### 3. The bug this backend was one keystroke away from having
The obvious API is `secret_password_store_sync` / `_lookup_sync` / `_clear_sync` — and that's what
the original Gap 3 brief named. Look at the password parameter: `const gchar*`. A NUL-terminated C
string.

`Vault::save` does `store_->set(service, encode_fields(fields))`, and `encode_fields` emits
**length-prefixed binary** — those length prefixes are small integers, so a saved record routinely
has NUL bytes in the middle. The simple API would truncate at the first one. No error, no warning:
a store that passes a casual eyeball test and silently corrupts every record.

So the code goes through the counted `SecretValue` layer instead:
```cpp
ValuePtr sv(secret_value_new(value.data(), static_cast<gssize>(value.size()),
                             "application/octet-stream"));
```
`secret_value_new` takes an explicit length; `secret_value_get` hands one back. Hence
`secret_service_store_sync` / `_lookup_sync` / `_clear_sync` / `_search_sync` rather than the
`secret_password_*` family. `SecretServiceStore.PreservesEmbeddedNuls` is the test that pins this —
it is the load-bearing one in the file.

### 4. Miss vs failure — the fail-closed seam
GLib reports through `GError**`, and both APIs return "nothing" on both a miss and a failure. The
distinction is the error object:

```cpp
if (!value) {
  if (err) fail("lookup for '" + name + "'", err);   // a failure — throw
  return std::nullopt;                               // a genuine miss
}
```
Collapsing those two into "not found" is precisely the silent downgrade the threat model forbids: a
daemon that's down or a keyring that's locked would read as "no such secret", and the caller would
happily prompt to create a new one on top of the existing entry. `remove()` has the mirror shape —
`secret_service_clear_sync` returns FALSE both when nothing matched and when the call failed, so the
GError is the only thing that separates "no-op" from "throw".

Error messages carry the *name* and GLib's description of the D-Bus failure. Never the value.

### 5. GLib lifetimes, with RAII bolted on
Four owning raw pointers cross these calls (`GError*`, `SecretValue*`, `GHashTable*`, `GList*`), and
every function has a throwing path. Rather than hand-freeing on each exit like the Windows backend
does with `CredFree`, there are four stateless deleters and `unique_ptr` aliases:

```cpp
using ErrorPtr    = std::unique_ptr<GError, GErrorDeleter>;
using ValuePtr    = std::unique_ptr<SecretValue, SecretValueDeleter>;
using AttrsPtr    = std::unique_ptr<GHashTable, HashTableDeleter>;
using ItemListPtr = std::unique_ptr<GList, ItemListDeleter>;
```
Stateless deleters cost nothing over the bare pointer. The `GList` one is the interesting deleter —
`g_list_free_full(l, g_object_unref)` frees the list *and* drops a ref on each `SecretItem` in it.

`secret_value_unref` is not merely a free: libsecret allocates secret memory from its own pool and
**wipes it** on unref. It's the counterpart of the `SecureZeroMemory` call in the Windows backend,
and the reason plain `g_free` would be wrong here.

### 6. Wiring
`defaultSecretStore` now mirrors macOS on Linux: the keyring in front, the `0600` file behind it via
`FallbackSecretStore`, so an existing file-stored secret stays readable and migrates on the next
`set`. We keep the fallback here even though Windows doesn't, because a `0600` file on Linux is a
genuine permission bit — a degraded store, not a fake one.

## Tests
- `tests/secret_service_store_test.cpp` — the contract oracle. Runs against the **real** keyring
  under a throwaway namespace (`keyward-test-secretservice`) and cleans up after itself. Skips
  rather than fails when libsecret is absent or there's no `DBUS_SESSION_BUS_ADDRESS` (headless,
  container, plain ssh). Deliberately does *not* widen that probe: if a bus exists but nothing
  answers, the test fails loudly rather than hiding a broken backend.
- `tests/linux_vault_smoke_test.cpp` — end-to-end `Vault::save/load<T>` over the live keyring,
  opt-in via `KEYWARD_HOST_TESTS=1`; plus an always-on check that `defaultSecretStore` really
  prefers the Secret Service.
- CI installs `libsecret-1-dev` + `gnome-keyring` on the ubuntu job and runs ctest inside
  `dbus-run-session` with the keyring unlocked, so the Linux job exercises this rather than skipping.

## Known limits (deliberate)
- **A locked keyring may block or fail.** A sync call can sit waiting on an unlock prompt. That's
  the OS asking for consent, which is the point — we do not paper over it by dropping to the file
  store.
- **No `SECRET_SEARCH_LOAD_SECRETS` in `list()`.** Listing needs attributes only; pulling every
  secret into memory to print names would be exposure for nothing.
- **Item labels are `keyward: <app>/<name>`** — visible in Seahorse. Names, never values.

## If you want this one hands-on
Say so and we revert to a scaffold + failing oracle and you write the bodies; the GLib lifetime
juggling (§5) and the miss-vs-failure seam (§4) are the parts worth the time.
