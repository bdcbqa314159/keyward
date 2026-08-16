cmake_minimum_required(VERSION 3.21)
project(keyward VERSION 0.1.0 LANGUAGES CXX C)  # C for vendored Monocypher

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # for clangd / editor language server

# --- vendored Monocypher --------------------------------------------------
# Argon2 + XChaCha20-Poly1305 for the encrypted-file backend. Its own target so
# our strict warning flags don't apply to third-party code. PIC so keyward can
# be built shared later.
add_library(monocypher STATIC third_party/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC third_party/monocypher)
set_target_properties(monocypher PROPERTIES POSITION_INDEPENDENT_CODE ON)

# --- fetched libsodium (audited secure memory + CSPRNG + constant-time) ----
# Via the robinlinden/libsodium-cmake wrapper, pinned (which pins libsodium via
# its submodule). PRIVATE to keyward — only secure_memory.cpp sees <sodium.h>.
include(FetchContent)
FetchContent_Declare(Sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG        9b2848dfc1b917a9410f0de9d81059b26cbfaa8d
)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Sodium)

# --- library --------------------------------------------------------------
# OS-agnostic secret store extracted from data_explorer. The macOS Keychain
# backend needs Apple frameworks; Monocypher stays a private implementation
# detail (linked privately below, never in a public header).
add_library(keyward
  src/file_secret_store.cpp
  src/keychain_secret_store.cpp        # macOS-only body; compiles empty elsewhere
  src/windows_credential_store.cpp     # Windows-only body; compiles empty elsewhere
  src/secret_service_store.cpp         # Linux+libsecret body; compiles empty elsewhere
  src/fallback_secret_store.cpp
  src/default_store.cpp
  src/random.cpp
  src/secret_box.cpp
  src/record_codec.cpp
  src/secure_memory.cpp
)
add_library(keyward::keyward ALIAS keyward)
target_compile_features(keyward PUBLIC cxx_std_20)
target_include_directories(keyward PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(keyward PRIVATE monocypher sodium)

# Strict warnings on our own code (vendored Monocypher, above, is exempt).
# PRIVATE so consumers don't inherit our warning flags.
if(MSVC)
  target_compile_options(keyward PRIVATE /W4)
else()
  target_compile_options(keyward PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(APPLE)
  target_link_libraries(keyward PUBLIC "-framework Security" "-framework CoreFoundation")
endif()

if(WIN32)
  target_link_libraries(keyward PUBLIC Advapi32)  # Credential Manager: CredWrite/Read/Delete
endif()

# --- optional Linux Secret Service backend (libsecret) --------------------
# Unlike Security.framework and Advapi32, libsecret does NOT ship with the OS —
# it's an optional system package. So we detect it rather than assume it, and a
# clone without it still builds (Linux then falls through to the 0600 file
# store). Install it with:
#   sudo apt install libsecret-1-dev     # Debian / Ubuntu
#   sudo dnf install libsecret-devel     # Fedora
#   sudo pacman -S libsecret             # Arch
# KEYWARD_HAVE_LIBSECRET is PUBLIC because the public header gates the class
# declaration on it, so consumers must see the same answer we compiled with.
# Includes and libs stay PRIVATE — <libsecret/secret.h> never reaches a public
# header. SYSTEM includes stop glib's headers tripping our -Wall -Wextra
# -Wpedantic (same trick as FTXUI below).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBSECRET QUIET libsecret-1)
  endif()
  if(LIBSECRET_FOUND)
    target_compile_definitions(keyward PUBLIC KEYWARD_HAVE_LIBSECRET)
    target_include_directories(keyward SYSTEM PRIVATE ${LIBSECRET_INCLUDE_DIRS})
    target_link_libraries(keyward PRIVATE ${LIBSECRET_LINK_LIBRARIES})
    message(STATUS "keyward: libsecret-1 ${LIBSECRET_VERSION} found — Secret Service backend ON")
  else()
    message(STATUS "keyward: libsecret-1 NOT found — Linux falls back to the 0600 file store")
  endif()
endif()

# --- optional CLI prompter component --------------------------------------
# keyward::cli — a terminal Prompter (no-echo for secrets). Its own target so
# core consumers that don't want a CLI never pull it in.
add_library(keyward_cli src/cli_prompter.cpp)
add_library(keyward::cli ALIAS keyward_cli)
target_link_libraries(keyward_cli PUBLIC keyward)
if(MSVC)
  target_compile_options(keyward_cli PRIVATE /W4)
else()
  target_compile_options(keyward_cli PRIVATE -Wall -Wextra -Wpedantic)
endif()

# --- optional TUI prompter component (needs FTXUI) ------------------------
# keyward::tui — an FTXUI form Prompter. Off unless top-level (a FetchContent
# consumer of keyward core never pays for FTXUI); flip -DKEYWARD_BUILD_TUI=ON to
# force it. FTXUI headers are treated as SYSTEM so their warnings don't trip ours.
option(KEYWARD_BUILD_TUI "Build the keyward::tui component (fetches FTXUI)" ${PROJECT_IS_TOP_LEVEL})
if(KEYWARD_BUILD_TUI)
  include(FetchContent)
  FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG        v5.0.0
    GIT_SHALLOW    TRUE
  )
  set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
  set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(ftxui)

  add_library(keyward_tui src/tui_prompter.cpp)
  add_library(keyward::tui ALIAS keyward_tui)
  target_link_libraries(keyward_tui PUBLIC keyward PRIVATE ftxui::component ftxui::dom ftxui::screen)
  target_include_directories(keyward_tui SYSTEM PRIVATE ${ftxui_SOURCE_DIR}/include)
  if(MSVC)
    target_compile_options(keyward_tui PRIVATE /W4)
  else()
    target_compile_options(keyward_tui PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endif()

# --- tests ----------------------------------------------------------------
# On by default when keyward is the top-level project; off when pulled in via
# FetchContent by a consumer.
option(KEYWARD_BUILD_TESTS "Build keyward tests" ${PROJECT_IS_TOP_LEVEL})
if(KEYWARD_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)  # for MSVC
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_executable(keyward_tests tests/secret_store_test.cpp)
  target_link_libraries(keyward_tests PRIVATE keyward GTest::gtest_main)
  include(GoogleTest)
  # Discover tests when ctest runs, not as a POST_BUILD step. POST_BUILD runs each
  # test exe during the build to enumerate tests and reads back a temp file, which
  # intermittently races under parallel builds (ParseTestList "file not found").
  set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)
  gtest_discover_tests(keyward_tests)

  # Task 1 — the Secret type. Red until include/keyward/secret.hpp exists.
  add_executable(secret_tests tests/secret_test.cpp)
  target_link_libraries(secret_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secret_tests)

  # Task 2 — constant-time compare. Red until Secret::equals exists.
  add_executable(secret_eq_tests tests/secret_eq_test.cpp)
  target_link_libraries(secret_eq_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secret_eq_tests)

  # Task 3 — seal/unseal. Red until src/secret_box.cpp is implemented.
  add_executable(secret_box_tests tests/secret_box_test.cpp)
  target_link_libraries(secret_box_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secret_box_tests)

  # Task 4 — record codec. Red until src/record_codec.cpp is implemented.
  add_executable(record_codec_tests tests/record_codec_test.cpp)
  target_link_libraries(record_codec_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(record_codec_tests)

  # Task 5 — typed schema mapping (header-only). Red until schema.hpp is filled.
  add_executable(schema_tests tests/schema_test.cpp)
  target_link_libraries(schema_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(schema_tests)

  # Task 6 — the Vault facade. Red until Vault::save/load are implemented.
  add_executable(vault_tests tests/vault_test.cpp)
  target_link_libraries(vault_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(vault_tests)

  # Authenticator seam — Vault's access-time gate (fake-authenticator oracle).
  add_executable(authenticator_tests tests/authenticator_test.cpp)
  target_link_libraries(authenticator_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(authenticator_tests)

  # Gap 3 — Windows Credential Manager backend. Red until the body is written
  # (skipped off Windows). Contract oracle for WindowsCredentialStore.
  add_executable(windows_credential_store_tests tests/windows_credential_store_test.cpp)
  target_link_libraries(windows_credential_store_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(windows_credential_store_tests)

  # Gap 3 — Linux Secret Service backend. Red until the body is written (skips
  # without libsecret, and on a box with no D-Bus session bus). Contract oracle
  # for SecretServiceStore.
  add_executable(secret_service_store_tests tests/secret_service_store_test.cpp)
  target_link_libraries(secret_service_store_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secret_service_store_tests)

  # Task 7 — Prompter protocol + Vault::ensure/revise (fake-prompter oracle).
  add_executable(prompter_tests tests/prompter_test.cpp)
  target_link_libraries(prompter_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(prompter_tests)

  # Gap 3 stretch — end-to-end Vault-over-real-Credential-Manager smoke test.
  # Opt-in (KEYWARD_HOST_TESTS=1); skips otherwise and off Windows.
  add_executable(windows_vault_smoke_tests tests/windows_vault_smoke_test.cpp)
  target_link_libraries(windows_vault_smoke_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(windows_vault_smoke_tests)

  # Gap 3 stretch — end-to-end Vault-over-real-Secret-Service smoke test, plus
  # the oracle for wiring defaultSecretStore to prefer the keyring on Linux.
  # The round-trip is opt-in (KEYWARD_HOST_TESTS=1); the wiring check always runs.
  add_executable(linux_vault_smoke_tests tests/linux_vault_smoke_test.cpp)
  target_link_libraries(linux_vault_smoke_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(linux_vault_smoke_tests)

  # Task 8 — the CLI prompter (keyward::cli), stream-injected oracle.
  add_executable(cli_prompter_tests tests/cli_prompter_test.cpp)
  target_link_libraries(cli_prompter_tests PRIVATE keyward_cli GTest::gtest_main)
  gtest_discover_tests(cli_prompter_tests)

  # Task 9 — the TUI prompter (keyward::tui). Only when the component is built.
  # Interactive form isn't headless-testable; this checks the title logic + that
  # it links and satisfies Prompter.
  if(KEYWARD_BUILD_TUI)
    add_executable(tui_prompter_tests tests/tui_prompter_test.cpp)
    target_link_libraries(tui_prompter_tests PRIVATE keyward_tui GTest::gtest_main)
    gtest_discover_tests(tui_prompter_tests)
  endif()
endif()

# --- fuzzers (opt-in; libFuzzer) ------------------------------------------
# The parsers take attacker-controlled bytes, so coverage-guided fuzzing is worth
# having. Off by default. NOTE: needs a Clang that ships the libFuzzer runtime —
# Apple's clang has the flag but NOT the runtime, so use Homebrew LLVM. Configure
# a DEDICATED build:
#   cmake -S . -B build/fuzz -DKEYWARD_BUILD_FUZZERS=ON -DKEYWARD_BUILD_TESTS=OFF -DKEYWARD_BUILD_TUI=OFF \
#     -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang \
#     -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
#   cmake --build build/fuzz
#   ./build/fuzz/fuzz_decode_fields -max_total_time=60
option(KEYWARD_BUILD_FUZZERS "Build libFuzzer harnesses for the parsers (Clang only)" OFF)
if(KEYWARD_BUILD_FUZZERS)
  # Coverage-instrument keyward for the fuzzer (this whole build is fuzz-only).
  target_compile_options(keyward PRIVATE -fsanitize=fuzzer-no-link,address)
  foreach(fuzz decode_fields unseal)
    add_executable(fuzz_${fuzz} tests/fuzz/fuzz_${fuzz}.cpp)
    target_link_libraries(fuzz_${fuzz} PRIVATE keyward)
    target_compile_options(fuzz_${fuzz} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_${fuzz} PRIVATE -fsanitize=fuzzer,address)
  endforeach()
endif()
