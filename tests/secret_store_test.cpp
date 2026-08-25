// SecretStore backends: file round-trip + fallback composition. No keychain
// (the macOS Keychain backend is exercised manually — it prompts).
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>  // inode check: proves the file is replaced, not rewritten
#endif

#include "keyward/fallback_secret_store.hpp"
#include "keyward/file_secret_store.hpp"

#if defined(_WIN32)
// clang-format off
#include <windows.h>
#include <aclapi.h>
// clang-format on
#endif

using namespace keyward;
namespace fs = std::filesystem;

TEST(FileSecretStore, RoundTrip) {
  const fs::path p = fs::temp_directory_path() / "keyward_test" / "credentials";
  std::error_code ec;
  fs::remove_all(p.parent_path(), ec);  // clean slate

  FileSecretStore s(p);
  EXPECT_FALSE(s.get("token").has_value());  // empty

  s.set("token", "abc123");
  EXPECT_EQ(s.get("token").value(), "abc123");

  s.set("token", "xyz789");  // overwrite, not append
  EXPECT_EQ(s.get("token").value(), "xyz789");

  s.set("other", "v");  // second key coexists
  EXPECT_EQ(s.get("other").value(), "v");
  EXPECT_EQ(s.get("token").value(), "xyz789");

  s.remove("token");
  EXPECT_FALSE(s.get("token").has_value());
  EXPECT_EQ(s.get("other").value(), "v");  // remove is surgical

#ifndef _WIN32
  // File must be owner-only (0600): no group/other bits.
  const auto perms = fs::status(p).permissions();
  EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
#endif

  fs::remove_all(p.parent_path(), ec);
}

// The credentials file must be REPLACED, never rewritten in place.
//
// This is the property the old implementation lacked. It opened the real file
// with std::ios::trunc, so anything interrupting the write — a crash, an OOM
// kill, a full disk — left it empty or half-written, losing every credential in
// it rather than just the one being stored.
//
// A genuine crash mid-write is not unit-testable, but the mechanism that makes
// it safe leaves a precise signature: rename(2) swaps in a different file, so
// the inode changes. Truncating in place keeps the same inode. Asserting the
// inode changed is therefore a direct test of "was this an atomic replace?",
// and it fails against the old implementation.
//
// The same mechanism is why a reader holding the file open keeps seeing a
// complete, consistent snapshot while a writer replaces it.
TEST(FileSecretStore, ReplacesTheFileRatherThanRewritingItInPlace) {
#if defined(_WIN32)
  GTEST_SKIP() << "inode semantics are POSIX; MoveFileEx provides the same guarantee";
#else
  const fs::path dir = fs::temp_directory_path() / "kw-atomic-replace";
  fs::remove_all(dir);
  const fs::path file = dir / "credentials";

  keyward::FileSecretStore store(file);
  store.set("jira", "ORIGINAL-TOKEN");

  struct stat before {};
  ASSERT_EQ(::stat(file.c_str(), &before), 0);

  store.set("jira", "REPLACEMENT-TOKEN");

  struct stat after {};
  ASSERT_EQ(::stat(file.c_str(), &after), 0);

  EXPECT_NE(before.st_ino, after.st_ino)
      << "the file kept its inode, so it was rewritten in place — an interrupted "
         "write would have destroyed every credential in it";
  EXPECT_EQ(store.get("jira").value_or("<lost>"), "REPLACEMENT-TOKEN");

  // No temp file may be left holding secrets.
  int leftovers = 0;
  for (const auto& entry : fs::directory_iterator(dir)) {
    if (entry.path().filename().string().find("kwtmp") != std::string::npos) ++leftovers;
  }
  EXPECT_EQ(leftovers, 0) << "a write left a temp file containing credentials behind";

  fs::remove_all(dir);
#endif
}

// The file must be owner-only from the moment it exists. The old path created it
// under the ambient umask and chmod'd afterwards, leaving a window in which the
// credentials file was readable by others.
TEST(FileSecretStore, IsOwnerOnlyImmediately) {
#if defined(_WIN32)
  GTEST_SKIP() << "POSIX mode bits do not apply; the DACL test covers Windows";
#else
  const fs::path dir = fs::temp_directory_path() / "kw-atomic-perms";
  fs::remove_all(dir);
  const fs::path file = dir / "credentials";

  keyward::FileSecretStore store(file);
  store.set("jira", "TOKEN");

  const auto mode = fs::status(file).permissions() & fs::perms::mask;
  EXPECT_EQ(mode, fs::perms::owner_read | fs::perms::owner_write) << "credentials file is not 0600";
  fs::remove_all(dir);
#endif
}

TEST(FileSecretStore, ListsStoredNames) {
  const fs::path p = fs::temp_directory_path() / "keyward_test_list" / "credentials";
  std::error_code ec;
  fs::remove_all(p.parent_path(), ec);

  FileSecretStore s(p);
  EXPECT_TRUE(s.list().empty());  // nothing stored yet

  s.set("alpha", "1");
  s.set("beta", "2");
  s.remove("alpha");  // removed names must not appear

  const std::vector<std::string> names = s.list();
  EXPECT_EQ(names.size(), 1u);
  EXPECT_NE(std::find(names.begin(), names.end(), "beta"), names.end());
  EXPECT_EQ(std::find(names.begin(), names.end(), "alpha"), names.end());

  fs::remove_all(p.parent_path(), ec);
}

#if defined(_WIN32)
TEST(FileSecretStore, WindowsDaclIsOwnerOnlyAndProtected) {
  const fs::path p = fs::temp_directory_path() / "keyward_test_dacl" / "credentials";
  std::error_code ec;
  fs::remove_all(p.parent_path(), ec);

  FileSecretStore(p).set("token", "secret");  // triggers the DACL lockdown
  ASSERT_TRUE(fs::exists(p));

  PSECURITY_DESCRIPTOR sd = nullptr;
  PACL dacl = nullptr;
  const DWORD rc =
      GetNamedSecurityInfoW(p.wstring().c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                            nullptr, &dacl, nullptr, &sd);
  ASSERT_EQ(rc, static_cast<DWORD>(ERROR_SUCCESS));
  ASSERT_NE(dacl, nullptr);

  // Inherited ACEs (e.g. the Users group) must be stripped, and only the owner
  // should remain — a single explicit ACE.
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ASSERT_TRUE(GetSecurityDescriptorControl(sd, &control, &revision));
  EXPECT_TRUE(control & SE_DACL_PROTECTED);
  EXPECT_EQ(dacl->AceCount, 1);

  if (sd != nullptr) LocalFree(sd);
  fs::remove_all(p.parent_path(), ec);
}
#endif  // _WIN32

TEST(FallbackSecretStore, ReadsFallbackThenMigratesToPrimary) {
  const fs::path base = fs::temp_directory_path() / "keyward_test_fb";
  std::error_code ec;
  fs::remove_all(base, ec);
  const fs::path pp = base / "primary", fp = base / "fallback";
  FileSecretStore(fp).set("K", "old");  // seed the fallback only

  FallbackSecretStore fb(std::make_unique<FileSecretStore>(pp),
                         std::make_unique<FileSecretStore>(fp));
  EXPECT_EQ(fb.get("K").value(), "old");  // served from fallback
  fb.set("K", "new");                     // migrates to primary AND evicts the fallback copy
  EXPECT_EQ(fb.get("K").value(), "new");  // primary now wins
  EXPECT_EQ(FileSecretStore(pp).get("K").value(), "new");
  EXPECT_FALSE(FileSecretStore(fp).get("K").has_value());  // fallback copy evicted (H1) — not stale

  fb.remove("K");  // remove clears both
  EXPECT_FALSE(FileSecretStore(pp).get("K").has_value());
  EXPECT_FALSE(FileSecretStore(fp).get("K").has_value());
  fs::remove_all(base, ec);
}
