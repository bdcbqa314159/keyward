# keyward

A small, cross-platform C++20 **credential SDK** — a thin, `keyring`-class facade
over the operating system's own credential manager (macOS Keychain, Linux
libsecret, Windows Credential Manager), with a portable encrypted-file fallback
for headless environments.

keyward does **not** roll its own vault: at-rest security is delegated to the
audited OS stores. keyward's job is correct integration, a flexible credential
schema, and not leaking secrets while they pass through your process. See
[docs/DESIGN.md](docs/DESIGN.md) for the full shape and roadmap.

> **Status — feature-complete core, pre-1.0.** Shipped: schema-typed records over
> a `Vault`; **native backends on macOS Keychain, Windows Credential Manager, and
> Linux Secret Service** (with an *encrypted*-file fallback); CLI + TUI prompters;
> an access gate (passphrase / biometric / fallback); libsodium secure-memory
> hardening. The remaining review-gated epic is the **agent daemon**.
>
> **Trust bound (read before use):** keyward is **personal-grade and not
> independently audited** — suitable for *your own* credentials on *your own*
> machine (macOS strongest). **Do not** entrust others' high-value secrets,
> shared/server machines, or catastrophic-if-breached credentials to it yet — for
> that, use a certified secrets manager (HashiCorp Vault, or a cloud Secret
> Manager) with short-lived credentials. See [SECURITY.md](SECURITY.md),
> [THREAT_MODEL.md](docs/THREAT_MODEL.md), and the audit plan in
> [SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md).

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

## Typed records — the `Vault` API

Declare a credential type and its fields; keyward stores the whole record as one
item in the OS credential manager, and a prompter collects it on first run. The
schema drives storage, masking, and typed access from a single declaration:

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
keyward::CliPrompter cli;                                 // or keyward::TuiPrompter
auto jira = vault.ensure<JiraCredential>("jira", cli);   // prompt on first run, then load
```

An optional access gate can require a passphrase or biometric before a secret is
released — "biometric if available, else passphrase":

```cpp
keyward::Vault vault{"myapp",
    std::make_unique<keyward::FallbackAuthenticator>(
        std::make_unique<keyward::BiometricAuthenticator>("Use passphrase"),
        std::make_unique<keyward::PassphraseAuthenticator>(verifier, source))};
```

Where no OS keychain exists (Linux without libsecret, BSD, containers), the file
fallback can encrypt at rest — pass a `KeyProvider`, or set `KEYWARD_PASSPHRASE`
for a headless deployment:

```cpp
auto store = keyward::defaultSecretStore("myapp",
    std::make_unique<keyward::PassphraseKeyProvider>(source));   // encrypted file fallback
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

## Implementing the contract (CLI, TUI, GUI)

keyward decides *what* is asked for; your application implements the window that
asks it. The contract is stated in `include/keyward/prompter.hpp` and
`include/keyward/authenticator.hpp` as obligations on the implementer — read those
two headers, not our implementations.

It is also **checkable**. `keyward/testing/conformance.hpp` ships with the library
and is framework-agnostic (no gtest, no macros, no exceptions), so you can run it
from whatever test setup you already have:

```cpp
#include "keyward/testing/conformance.hpp"

const std::vector<keyward::PromptField> before = /* what the SDK hands you */;
std::vector<keyward::PromptField> after = before;
const bool accepted = my_prompt_window.collect("jira", reason, after);

auto report = accepted ? keyward::testing::check_accepted(before, after)
                       : keyward::testing::check_cancelled(before, after);
ASSERT_TRUE(report.conforms()) << report.summary();
```

The one obligation worth reading twice: an `Authenticator` that cannot ask must
return **`Unavailable`**, never `Denied`. Only `Unavailable` lets a
`FallbackAuthenticator` try the next tier — returning `Denied` strands the user
with no way forward. `check_authenticator_when_unavailable()` catches exactly that.

### The reference implementations

`keyward::cli` is a compiled component you link. **The FTXUI prompter is a
header** — include it and it compiles against *your* FTXUI:

```cpp
#include <keyward/tui_prompter.hpp>     // you supply FTXUI (e.g. libftxui-dev)

keyward::TuiPrompter prompter;
auto cred = vault.ensure<JiraCredential>("jira", prompter);
```

There is no `keyward::tui` library to find or link. That is deliberate: the only
app that wants an FTXUI prompter already links FTXUI, and a second copy of a
header-heavy C++ library in one binary is an ODR hazard — a silent one. Compiling
~100 lines in your own translation unit avoids it, along with any version pin from
us and any ABI mismatch from our build flags. CI proves the path by building this
against the distro's `libftxui-dev` rather than the version keyward pins.

The same shape answers any other toolkit: a Qt or ImGui prompter would also be a
header you compile against your own stack. keyward ships the contract plus
reference implementations; the toolkit stays yours.

The FTXUI prompter runs its own modal loop inside `collect()`, so **the host
application must cede the terminal** for the duration of the call.

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
