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
# BUILD_INTERFACE only: keyward's sources need monocypher.h while building, but
# consumers never see it (it is a private implementation detail), and a bare
# source-tree path cannot be exported by install(EXPORT).
target_include_directories(monocypher PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/monocypher>)
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

# The CMake wrapper performs NO feature detection — it defines only CONFIGURED —
# so libsodium compiled its FALLBACK allocator and sodium_malloc behaved as plain
# malloc. Measured before this: no guard pages (a read one byte past a 64-byte
# allocation succeeded, and the pointer sat at page offset 0x10 instead of flush
# against a trailing guard), no `lo` VmFlag (so secrets could reach swap) and no
# `dd` VmFlag (so secrets landed in core dumps). Zeroing on free still worked;
# the page protections did not, despite what Secret's header claimed.
#
# libsodium gates them on plain feature macros, so detect the primitives and hand
# them over. Where a platform lacks them (Windows has no sys/mman.h) nothing is
# defined and behaviour is exactly as before.
#   HAVE_MMAP + MAP_ANON, or HAVE_POSIX_MEMALIGN -> HAVE_ALIGNED_MALLOC
#   ... plus HAVE_MPROTECT                       -> HAVE_PAGE_PROTECTION (guard pages)
#   HAVE_MLOCK                                   -> no swap
#   HAVE_MADVISE                                 -> MADV_DONTDUMP (out of core dumps)
include(CheckSymbolExists)
include(CheckIncludeFile)
# libsodium only includes <sys/mman.h> under HAVE_SYS_MMAN_H, so without this the
# mlock/mprotect calls compile as implicit declarations and the build fails.
check_include_file("sys/mman.h" KEYWARD_SYS_HAVE_SYS_MMAN_H)
check_symbol_exists(mmap           "sys/mman.h" KEYWARD_SYS_HAVE_MMAP)
check_symbol_exists(mprotect       "sys/mman.h" KEYWARD_SYS_HAVE_MPROTECT)
check_symbol_exists(mlock          "sys/mman.h" KEYWARD_SYS_HAVE_MLOCK)
check_symbol_exists(madvise        "sys/mman.h" KEYWARD_SYS_HAVE_MADVISE)
check_symbol_exists(posix_memalign "stdlib.h"   KEYWARD_SYS_HAVE_POSIX_MEMALIGN)
# Load-bearing: libsodium only learns the real page size from sysconf(_SC_PAGESIZE)
# when HAVE_SYSCONF is set. Enable the allocator without it and it builds fine,
# then aborts at runtime on its own page-arithmetic assertion.
check_symbol_exists(sysconf        "unistd.h"   KEYWARD_SYS_HAVE_SYSCONF)

set(_keyward_sodium_features "")
foreach(feat SYS_MMAN_H MMAP MPROTECT MLOCK MADVISE POSIX_MEMALIGN SYSCONF)
  if(KEYWARD_SYS_HAVE_${feat})
    list(APPEND _keyward_sodium_features HAVE_${feat})
  endif()
endforeach()
if(_keyward_sodium_features)
  # PRIVATE: this only changes how libsodium itself is compiled.
  target_compile_definitions(sodium PRIVATE ${_keyward_sodium_features})
  message(STATUS "keyward: libsodium memory protections enabled — ${_keyward_sodium_features}")
else()
  message(STATUS "keyward: no mman primitives detected — libsodium keeps its fallback allocator")
endif()

# --- library --------------------------------------------------------------
# OS-agnostic secret store extracted from data_explorer. The macOS Keychain
# backend needs Apple frameworks; Monocypher stays a private implementation
# detail (linked privately below, never in a public header).
add_library(keyward
  src/file_secret_store.cpp
  src/keychain_secret_store.cpp        # macOS-only body; compiles empty elsewhere
  src/windows_credential_store.cpp     # Windows-only body; compiles empty elsewhere
  src/secret_service_store.cpp         # Linux+libsecret body; compiles empty elsewhere
  src/polkit_authenticator.cpp         # Linux+polkit body; compiles empty elsewhere
  src/fallback_secret_store.cpp
  src/default_store.cpp
  src/random.cpp
  src/secret_box.cpp
  src/record_codec.cpp
  src/secure_memory.cpp
  src/passphrase_authenticator.cpp
  src/biometric_authenticator.cpp  # Objective-C++ on Apple (see -x below); plain C++ elsewhere
)
add_library(keyward::keyward ALIAS keyward)
target_compile_features(keyward PUBLIC cxx_std_20)
target_include_directories(keyward PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(keyward PRIVATE monocypher sodium)

# Only secure_memory.cpp includes <sodium.h>; nothing outside keyward ever does.
# The wrapper publishes the headers through sodium's INTERFACE_INCLUDE_DIRECTORIES
# as raw build-tree paths, and install(EXPORT) refuses those ("path is prefixed in
# the build directory"). Take the paths onto keyward as a private include, then
# clear sodium's interface so the target becomes exportable. Consumers lose
# nothing, because they never include libsodium headers through us.
get_target_property(_keyward_sodium_includes sodium INTERFACE_INCLUDE_DIRECTORIES)
if(_keyward_sodium_includes)
  target_include_directories(keyward SYSTEM PRIVATE ${_keyward_sodium_includes})
  set_target_properties(sodium PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "")
endif()

# Strict warnings on our own code (vendored Monocypher, above, is exempt).
# PRIVATE so consumers don't inherit our warning flags.
if(MSVC)
  target_compile_options(keyward PRIVATE /W4)
else()
  target_compile_options(keyward PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(APPLE)
  target_link_libraries(keyward PUBLIC "-framework Security" "-framework CoreFoundation")
  # Biometric backend: LocalAuthentication (Touch ID). The source is a .cpp, so
  # compile just this one as Objective-C++ here (plain C++ everywhere else).
  set_source_files_properties(src/biometric_authenticator.cpp PROPERTIES
    COMPILE_OPTIONS "-x;objective-c++")
  target_link_libraries(keyward PUBLIC "-framework LocalAuthentication" "-framework Foundation")
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

# --- optional Linux polkit authenticator ----------------------------------
# Linux has no Touch ID / Windows Hello equivalent, so presence checks go through
# the desktop's authorization broker instead. Like libsecret, polkit is NOT part
# of every Linux, so it is detected rather than assumed and the backend compiles
# away when absent.
#
# Being useful also needs packaging/com.keyward.policy installed into
# /usr/share/polkit-1/actions/ — polkit will not reason about an action it does
# not know. PolkitAuthenticator reports Unavailable in that case, so a
# FallbackAuthenticator degrades to the passphrase tier instead of locking anyone
# out. Install rules land with the packaging work.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(POLKIT QUIET polkit-gobject-1)
  endif()
  if(POLKIT_FOUND)
    target_compile_definitions(keyward PUBLIC KEYWARD_HAVE_POLKIT)
    target_include_directories(keyward SYSTEM PRIVATE ${POLKIT_INCLUDE_DIRS})
    target_link_libraries(keyward PRIVATE ${POLKIT_LINK_LIBRARIES})
    message(STATUS "keyward: polkit-gobject-1 ${POLKIT_VERSION} found — Linux presence checks ON")
  else()
    message(STATUS "keyward: polkit-gobject-1 NOT found — Linux has no presence-check tier")
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

# --- TUI prompter: header-only, no target to link -------------------------
# keyward::tui used to be a compiled library that was never installed and never
# built for consumers — so the TUI, a stated headline feature, did not actually
# ship. It is now a header (include/keyward/tui_prompter.hpp), which is the
# natural unit for ~100 lines adapting to somebody else's UI library:
#
#   - the only app that wants it already links FTXUI, so compiling it in THEIR
#     translation unit against THEIR FTXUI avoids a second copy of a header-heavy
#     C++ library in one binary — an ODR hazard, and a silent one;
#   - no version pin, no ABI fragility from our flags, nothing to install beyond
#     the headers we already install.
#
# It matches the house style: the parts that adapt to a caller's types or toolkit
# are headers (schema, vault, fallback_authenticator); the parts owning platform
# code or state are compiled.
#
# FTXUI is fetched here only so OUR tests and examples compile the header against
# a pinned version. Consumers supply their own (libftxui-dev, or FetchContent).
option(KEYWARD_BUILD_TUI "Fetch FTXUI so keyward's own TUI tests build" ${PROJECT_IS_TOP_LEVEL})
if(KEYWARD_BUILD_TUI)
  include(FetchContent)
  FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG        v5.0.0
    GIT_SHALLOW    TRUE
  )
  # Without this, `cmake --install` on keyward also installs FTXUI's libraries and
  # headers into our prefix — a keyward package must not ship someone else's.
  set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
  set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(ftxui)
endif()

# --- install / export -----------------------------------------------------
# Without this keyward is FetchContent-only: it cannot be packaged for a distro
# and find_package(keyward) does not work. Off when consumed as a subproject, so
# a FetchContent user never installs our files.
#
# The awkward part is dependencies. keyward is a STATIC library, so its objects
# do not contain monocypher's or libsodium's — a consumer has to link those too.
# libsodium arrives via FetchContent from a wrapper with no install rules of its
# own, so we install it ourselves, namespaced under keyward:: to keep it from
# colliding with a system libsodium.
option(KEYWARD_INSTALL "Generate install rules" ${PROJECT_IS_TOP_LEVEL})
if(KEYWARD_INSTALL)
  include(GNUInstallDirs)
  include(CMakePackageConfigHelpers)

  # No keyward_tui target any more: the TUI prompter is a header, and headers
  # are installed wholesale by the install(DIRECTORY) below.
  set(_keyward_install_targets keyward keyward_cli monocypher sodium)
  install(TARGETS ${_keyward_install_targets}
    EXPORT keywardTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(DIRECTORY include/keyward DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(EXPORT keywardTargets
    FILE keywardTargets.cmake
    NAMESPACE keyward::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keyward)

  configure_package_config_file(
    packaging/keywardConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/keywardConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keyward)
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/keywardConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/keywardConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/keywardConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keyward)

  # pkg-config, for consumers that do not use CMake.
  set(KEYWARD_PC_REQUIRES_PRIVATE "")
  set(KEYWARD_PC_CFLAGS "")
  if(LIBSECRET_FOUND)
    string(APPEND KEYWARD_PC_REQUIRES_PRIVATE "libsecret-1 ")
    string(APPEND KEYWARD_PC_CFLAGS "-DKEYWARD_HAVE_LIBSECRET ")
  endif()
  if(POLKIT_FOUND)
    string(APPEND KEYWARD_PC_REQUIRES_PRIVATE "polkit-gobject-1 ")
    string(APPEND KEYWARD_PC_CFLAGS "-DKEYWARD_HAVE_POLKIT ")
  endif()
  # Hop from <prefix>/<libdir>/pkgconfig back up to <prefix>, so the .pc can
  # resolve its own prefix from ${pcfiledir} instead of a baked-in path.
  file(RELATIVE_PATH KEYWARD_PC_REL_PREFIX
       "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" "${CMAKE_INSTALL_PREFIX}")
  string(REGEX REPLACE "/$" "" KEYWARD_PC_REL_PREFIX "${KEYWARD_PC_REL_PREFIX}")
  configure_file(packaging/keyward.pc.in ${CMAKE_CURRENT_BINARY_DIR}/keyward.pc @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/keyward.pc
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  # The polkit action. PolkitAuthenticator reports Unavailable until this is in
  # place, so shipping the library without it leaves the tier permanently off.
  if(POLKIT_FOUND)
    install(FILES packaging/com.keyward.policy
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/polkit-1/actions)
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
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)  # test dep: never part of our package
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

  # PassphraseAuthenticator + verifier (Argon2id, scripted-source oracle).
  add_executable(passphrase_authenticator_tests tests/passphrase_authenticator_test.cpp)
  target_link_libraries(passphrase_authenticator_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(passphrase_authenticator_tests)

  # FallbackAuthenticator policy (fakes) + a link/availability smoke of Biometric.
  add_executable(fallback_authenticator_tests tests/fallback_authenticator_test.cpp)
  target_link_libraries(fallback_authenticator_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(fallback_authenticator_tests)

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

  # Gap 3 interop — keyward <-> Python `keyring` over the same Secret Service,
  # pinning DESIGN.md's compatibility north star. Needs the pinned keyring from
  # requirements-dev.txt in the local .venv (or one on PATH); without it the
  # test compiles to a skip that says how to get it.
  find_program(KEYWARD_KEYRING_CLI keyring
    HINTS ${CMAKE_CURRENT_SOURCE_DIR}/.venv/bin
    NO_CMAKE_SYSTEM_PATH)
  add_executable(secret_service_interop_tests tests/secret_service_interop_test.cpp)
  target_link_libraries(secret_service_interop_tests PRIVATE keyward GTest::gtest_main)
  if(KEYWARD_KEYRING_CLI)
    target_compile_definitions(secret_service_interop_tests
      PRIVATE KEYWARD_KEYRING_CLI="${KEYWARD_KEYRING_CLI}")
    message(STATUS "keyward: keyring CLI at ${KEYWARD_KEYRING_CLI} — interop tests ON")
  else()
    message(STATUS "keyward: no keyring CLI — interop tests SKIP "
                   "(.venv/bin/pip install -r requirements-dev.txt)")
  endif()
  gtest_discover_tests(secret_service_interop_tests)

  # Gap 3 hardening — locked-keyring behaviour. Registered by hand rather than
  # via gtest_discover_tests because it MUST go through the isolation wrapper:
  # it locks the default collection, which would otherwise lock the developer's
  # real login keyring. Exit 77 from the wrapper means "tooling absent" -> skip.
  add_executable(secret_service_locked_tests tests/secret_service_locked_test.cpp)
  target_link_libraries(secret_service_locked_tests PRIVATE keyward GTest::gtest_main)
  # Registered only where a POSIX shell can run the wrapper. Windows ctest reports
  # BAD_COMMAND for a .sh COMMAND — a red job, not a skip. The executable is still
  # built everywhere so the file stays compiled and warning-checked on all three
  # OSes; off Linux its body is a single GTEST_SKIP anyway. On macOS the wrapper
  # exits 77 (no gnome-keyring) and ctest reports a skip.
  if(UNIX)
    add_test(NAME SecretServiceLocked.Isolated
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_isolated_keyring.sh
                     $<TARGET_FILE:secret_service_locked_tests>)
    set_tests_properties(SecretServiceLocked.Isolated PROPERTIES SKIP_RETURN_CODE 77)
  endif()

  # Regression test for a SILENT build-config failure: libsodium's memory
  # protections were compiled out, so secure_alloc was plain malloc.
  add_executable(secure_memory_protection_tests tests/secure_memory_protection_test.cpp)
  target_link_libraries(secure_memory_protection_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secure_memory_protection_tests)

  # The shipped conformance suite, run against our own references AND against
  # deliberately broken ones — a checker that cannot fail is worthless.
  add_executable(conformance_tests tests/conformance_test.cpp)
  target_link_libraries(conformance_tests PRIVATE keyward_cli GTest::gtest_main)
  gtest_discover_tests(conformance_tests)

  # Harden pass — SecureString / SecureAllocator: no plaintext left in the
  # buffers a growing string releases.
  add_executable(secure_string_tests tests/secure_string_test.cpp)
  target_link_libraries(secure_string_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(secure_string_tests)

  # Linux presence checks via polkit. The granted path needs a live agent, so
  # what runs headlessly is the Unavailable/Denied mapping — see the test.
  add_executable(polkit_authenticator_tests tests/polkit_authenticator_test.cpp)
  target_link_libraries(polkit_authenticator_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(polkit_authenticator_tests)

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
    # Compiles the header-only prompter against pinned FTXUI, exactly as a
    # consumer would against their own.
    add_executable(tui_prompter_tests tests/tui_prompter_test.cpp)
    target_link_libraries(tui_prompter_tests
      PRIVATE keyward GTest::gtest_main ftxui::component ftxui::dom ftxui::screen)
    target_include_directories(tui_prompter_tests SYSTEM PRIVATE ${ftxui_SOURCE_DIR}/include)
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
#   mkdir -p build/fuzz/found   # libFuzzer WRITES new units to the first dir;
#   ./build/fuzz/fuzz_decode_fields build/fuzz/found \
#     tests/fuzz/corpus/decode_fields -max_total_time=60   # seeds stay read-only
#
# On Linux use the system clang (CI does). If it fails to link with
# "cannot find -lstdc++", clang picked a GCC install with no libstdc++ headers;
# point it at one that has them, e.g.
#   -DCMAKE_CXX_FLAGS=--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/15
#
# Seed corpora live in tests/fuzz/corpus/<harness>/ — pass a scratch dir first
# (libFuzzer writes discoveries there), the seed dir second. For decode_fields
# the seeds are worth ~55% more new coverage units per minute.
#
# This build tree also weakens the Argon2 cost (KEYWARD_FUZZ_CHEAP_KDF, below).
# Without it unseal managed 12 executions in 21 seconds, because every seeded
# input is past the 56-byte header and pays a full Argon2id over 100 MB; with it,
# ~6.5k/s. That is why this tree must never be the one you ship or test.
option(KEYWARD_BUILD_FUZZERS "Build libFuzzer harnesses for the parsers (Clang only)" OFF)
if(KEYWARD_BUILD_FUZZERS)
  # This build tree's crypto is DELIBERATELY WEAKENED (see below), so it must not
  # also produce the test suite: a green run there would be green against a token
  # KDF. The documented fuzz configure already passes -DKEYWARD_BUILD_TESTS=OFF;
  # this makes forgetting it an error instead of a false pass.
  if(KEYWARD_BUILD_TESTS)
    message(FATAL_ERROR
      "KEYWARD_BUILD_FUZZERS weakens the Argon2 cost for throughput; it cannot share a "
      "build tree with the tests. Configure a dedicated one with -DKEYWARD_BUILD_TESTS=OFF.")
  endif()

  # Coverage-instrument keyward for the fuzzer (this whole build is fuzz-only).
  target_compile_options(keyward PRIVATE -fsanitize=fuzzer-no-link,address)

  # Argon2 at production cost makes unseal() unfuzzable: 100 MB of work memory
  # per input past the 56-byte header, measured at 12 executions in 21 seconds.
  # The KDF cost is orthogonal to the branches a fuzzer explores (header parse,
  # length arithmetic, AEAD verify), so this trades cost for throughput without
  # changing what is covered. PRIVATE, and only inside this if(), so no normal
  # configure on any OS ever sees it — a Release build is byte-identical with or
  # without this block. src/secret_box.cpp also emits a #warning when it is on.
  target_compile_definitions(keyward PRIVATE KEYWARD_FUZZ_CHEAP_KDF)
  foreach(fuzz decode_fields unseal)
    add_executable(fuzz_${fuzz} tests/fuzz/fuzz_${fuzz}.cpp)
    target_link_libraries(fuzz_${fuzz} PRIVATE keyward)
    target_compile_options(fuzz_${fuzz} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_${fuzz} PRIVATE -fsanitize=fuzzer,address)
  endforeach()
endif()
