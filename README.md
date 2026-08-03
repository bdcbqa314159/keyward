# keyward

A small, cross-platform C++20 **credential-manager SDK** — store named secrets in
the OS keychain where available, with a portable file fallback, behind one
`SecretStore` interface.

> **Status: Phase 0** — the OS-agnostic secret store, extracted from the
> `data_explorer` project. macOS Keychain backend + `0600` file fallback +
> fallback composition. Records, cross-platform backends (Windows Credential
> Manager, Linux libsecret), an encrypted-file backend, an authenticator layer,
> and an ssh-agent-style agent are planned next.

## Use

```cpp
#include <keyward/default_store.hpp>

auto store = keyward::defaultSecretStore("myapp");   // keychain in front of a 0600 file
store->set("api_key", "s3cr3t");
if (auto v = store->get("api_key")) { /* use *v */ }
store->remove("api_key");
```

Or pick a backend directly (`keyward::FileSecretStore`, `keyward::KeychainSecretStore`,
`keyward::FallbackSecretStore`).

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Consume via FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(keyward GIT_REPOSITORY <repo-url> GIT_TAG main)
FetchContent_MakeAvailable(keyward)
target_link_libraries(your_app PRIVATE keyward::keyward)
```

## License

MIT — see [LICENSE](LICENSE).
