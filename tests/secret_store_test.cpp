// SecretStore backends: file round-trip + fallback composition. No keychain
// (the macOS Keychain backend is exercised manually — it prompts).
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>

#include "keyward/fallback_secret_store.hpp"
#include "keyward/file_secret_store.hpp"

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

TEST(FallbackSecretStore, ReadsFallbackThenMigratesToPrimary) {
  const fs::path base = fs::temp_directory_path() / "keyward_test_fb";
  std::error_code ec;
  fs::remove_all(base, ec);
  const fs::path pp = base / "primary", fp = base / "fallback";
  FileSecretStore(fp).set("K", "old");  // seed the fallback only

  FallbackSecretStore fb(std::make_unique<FileSecretStore>(pp),
                         std::make_unique<FileSecretStore>(fp));
  EXPECT_EQ(fb.get("K").value(), "old");  // served from fallback
  fb.set("K", "new");                     // migrates to primary
  EXPECT_EQ(fb.get("K").value(), "new");  // primary now wins
  EXPECT_EQ(FileSecretStore(pp).get("K").value(), "new");
  EXPECT_EQ(FileSecretStore(fp).get("K").value(), "old");  // fallback untouched by set

  fb.remove("K");  // remove clears both
  EXPECT_FALSE(FileSecretStore(pp).get("K").has_value());
  EXPECT_FALSE(FileSecretStore(fp).get("K").has_value());
  fs::remove_all(base, ec);
}
