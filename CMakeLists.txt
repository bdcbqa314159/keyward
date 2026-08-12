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

# --- library --------------------------------------------------------------
# OS-agnostic secret store extracted from data_explorer. The macOS Keychain
# backend needs Apple frameworks; Monocypher stays a private implementation
# detail (linked privately below, never in a public header).
add_library(keyward
  src/file_secret_store.cpp
  src/keychain_secret_store.cpp        # macOS-only body; compiles empty elsewhere
  src/windows_credential_store.cpp     # Windows-only body; compiles empty elsewhere
  src/fallback_secret_store.cpp
  src/default_store.cpp
  src/random.cpp
  src/secret_box.cpp
  src/record_codec.cpp
)
add_library(keyward::keyward ALIAS keyward)
target_compile_features(keyward PUBLIC cxx_std_20)
target_include_directories(keyward PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(keyward PRIVATE monocypher)

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

  # Gap 3 — Windows Credential Manager backend. Red until the body is written
  # (skipped off Windows). Contract oracle for WindowsCredentialStore.
  add_executable(windows_credential_store_tests tests/windows_credential_store_test.cpp)
  target_link_libraries(windows_credential_store_tests PRIVATE keyward GTest::gtest_main)
  gtest_discover_tests(windows_credential_store_tests)
endif()
