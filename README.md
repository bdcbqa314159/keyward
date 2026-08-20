# keyward

A small, cross-platform C++20 **credential SDK** — a thin, `keyring`-class facade
over the operating system's own credential manager (macOS Keychain, Linux
libsecret, Windows Credential Manager), with a portable encrypted-file fallback
for headless environments.

keyward does **not** roll its own vault: at-rest security is delegated to the
audited OS stores. keyward's job is correct integration, a flexible credential
schema, and not leaking secrets while they pass through your process. See
[docs/DESIGN.md](docs/DESIGN.md) for the full shape and roadmap.

> **Status — in progress.** Working today: the `SecretStore` interface with a
> three-tier resolver (env var → OS keychain → `0600` file), a macOS Keychain
> backend, and a passphrase-based encrypted blob (`seal`/`unseal`, Argon2id +
> XChaCha20-Poly1305 via vendored Monocypher). Next up: the schema-driven
> typed-record `Vault` API, the Linux/Windows backends, an in-process hardening
> pass (libsodium secure memory), and a small TUI front-end. Not yet reviewed
> for production use — see [SECURITY.md](SECURITY.md).

## Use today

```cpp
#include <keyward/default_store.hpp>

auto store = keyward::defaultSecretStore("myapp");   // keychain in front of a 0600 file
store->set("api_key", "s3cr3t");
if (auto v = store->get("api_key")) { /* use *v */ }
store->remove("api_key");
```

Or pick a backend directly (`keyward::FileSecretStore`, `keyward::KeychainSecretStore`,
`keyward::FallbackSecretStore`).

Encrypt a secret under a passphrase into a self-contained blob (safe to write to
a `0600` file), and back:

```cpp
#include <keyward/secret_box.hpp>

std::string blob = keyward::seal("s3cr3t", passphrase);   // salt‖nonce‖mac‖ciphertext
if (auto plain = keyward::unseal(blob, passphrase)) { /* use *plain */ }
```

## Where it's heading

The developer declares a credential type and its fields; keyward stores the
record as one item in the OS credential manager, and a TUI collects it on first
run. Sketch (**not yet implemented** — see [docs/DESIGN.md](docs/DESIGN.md)):

```cpp
struct JiraCredential {
  std::string email, url, token;
  static keyward::Schema<JiraCredential> schema() {
    return {{"email", &JiraCredential::email},
            {"url",   &JiraCredential::url},
            {"token", &JiraCredential::token, keyward::Sensitive}};
  }
};

keyward::Vault vault{"myapp"};
auto jira = vault.ensure<JiraCredential>("jira", tui);   // prompt on first run, then load
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Sanitizers

CI runs the whole suite under ASan + UBSan + LSan on Linux. Locally:

```bash
cmake --preset asan && cmake --build build/asan -j
ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build/asan --output-on-failure
```

The preset passes `-fno-sanitize-recover=all` on purpose: UBSan otherwise just
prints a diagnostic and lets the process exit 0, so a finding would leave the
suite green.

### Optional Linux extras

Some tests need system packages and skip (loudly) without them:

```bash
sudo apt install libsecret-1-dev              # Secret Service backend + its tests
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
```

The venv provides the pinned `clang-format` and the `keyring` used as the other
side of the Secret Service interop test. Configure output tells you which
optional pieces are on.

## Consume via FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(keyward GIT_REPOSITORY <repo-url> GIT_TAG main)
FetchContent_MakeAvailable(keyward)
target_link_libraries(your_app PRIVATE keyward::keyward)
```

## Install and consume

**No root required, and no reconfiguring for a different prefix.** Pick any
directory you can write to:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build --prefix ~/.local        # or /opt/keyward, or a staging dir
```

Then either route works:

```cmake
# CMake
find_package(keyward REQUIRED)                 # cmake -DCMAKE_PREFIX_PATH=~/.local
target_link_libraries(your_app PRIVATE keyward::keyward)
```

```bash
# pkg-config — note --static: keyward is a static library, so its private
# dependencies (libsecret, polkit, libsodium) only appear with that flag.
export PKG_CONFIG_PATH=~/.local/lib/pkgconfig
g++ -std=c++20 $(pkg-config --cflags keyward) app.cpp $(pkg-config --static --libs keyward)
```

`packaging/consumer-test/` is a working example of the CMake route, and CI builds
it against a freshly installed prefix on every PR.

### What gets installed
`libkeyward.a` plus its vendored `libmonocypher.a` and `libsodium.a` (a static
keyward does not contain their objects, so consumers need them), the public
headers, the CMake package files, `keyward.pc`, and — on Linux with polkit —
`share/polkit-1/actions/com.keyward.policy`.

### One thing a user-prefix install cannot do
polkit only reads actions from the **system** directory (`/usr/share/polkit-1/actions`).
Installed under `~/.local`, the policy file lands somewhere polkit never looks, so
`PolkitAuthenticator` reports `Unavailable` and a `FallbackAuthenticator` degrades
to the passphrase tier. That is the designed behaviour, not a failure — but if you
want the polkit tier, that one file needs a root-owned system install:

```bash
sudo install -m 644 packaging/com.keyward.policy /usr/share/polkit-1/actions/
```

## License

MIT — see [LICENSE](LICENSE).
