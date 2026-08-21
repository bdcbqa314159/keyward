// FileSecretStore encryption mode: sealed entries, key-less list/remove, legacy
// migration, and fail-closed on a wrong passphrase or tampering. Uses a temp
// file and a scripted passphrase source (no tty).
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "keyward/encrypted_file_format.hpp"
#include "keyward/file_secret_store.hpp"
#include "keyward/key_provider.hpp"

namespace fs = std::filesystem;
using keyward::FileSecretStore;
using keyward::PassphraseKeyProvider;

namespace {

// A per-test temp path (tags are unique within this one test binary); removed on
// construction and destruction. No getpid — that isn't portable to Windows.
struct TempFile {
  fs::path path;
  explicit TempFile(const std::string& tag) : path(fs::temp_directory_path() / ("kw-enc-" + tag)) {
    fs::remove(path);
  }
  ~TempFile() { fs::remove(path); }
};

std::unique_ptr<PassphraseKeyProvider> provider(std::string pass) {
  return std::make_unique<PassphraseKeyProvider>(
      [pass = std::move(pass)](std::string_view) -> std::optional<std::string> { return pass; });
}

std::string readRaw(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

TEST(FileEncryption, RoundTripsAndFileIsEncrypted) {
  TempFile tmp("rt");
  {
    FileSecretStore store{tmp.path, provider("pw")};
    store.set("jira", "SUPER-SECRET");
    EXPECT_EQ(store.get("jira"), "SUPER-SECRET");
  }
  // On disk: magic header, and the plaintext must NOT appear.
  const std::string raw = readRaw(tmp.path);
  EXPECT_TRUE(keyward::is_encrypted_file(raw));
  EXPECT_EQ(raw.find("SUPER-SECRET"), std::string::npos);
  // A fresh store with the same passphrase reads it back.
  FileSecretStore reopened{tmp.path, provider("pw")};
  EXPECT_EQ(reopened.get("jira"), "SUPER-SECRET");
}

TEST(FileEncryption, MultipleEntriesAndUpdate) {
  TempFile tmp("multi");
  FileSecretStore store{tmp.path, provider("pw")};
  store.set("a", "1");
  store.set("b", "2");
  store.set("a", "updated");
  EXPECT_EQ(store.get("a"), "updated");
  EXPECT_EQ(store.get("b"), "2");
  EXPECT_FALSE(store.get("missing").has_value());
}

TEST(FileEncryption, ListAndRemoveNeedNoPassphrase) {
  TempFile tmp("keyless");
  {
    FileSecretStore store{tmp.path, provider("pw")};
    store.set("a", "1");
    store.set("b", "2");
  }
  // A provider that would THROW if ever asked for a passphrase.
  auto exploding =
      std::make_unique<PassphraseKeyProvider>([](std::string_view) -> std::optional<std::string> {
        ADD_FAILURE() << "list/remove must not unlock";
        return std::nullopt;
      });
  FileSecretStore store{tmp.path, std::move(exploding)};
  auto names = store.list();
  EXPECT_EQ(names.size(), 2u);
  store.remove("a");  // also must not prompt
  EXPECT_EQ(store.list().size(), 1u);
}

TEST(FileEncryption, WrongPassphraseThrows) {
  TempFile tmp("wrongpw");
  {
    FileSecretStore store{tmp.path, provider("right")};
    store.set("jira", "secret");
  }
  FileSecretStore store{tmp.path, provider("wrong")};
  EXPECT_THROW(store.get("jira"), std::runtime_error);  // fail closed, not "no such secret"
}

TEST(FileEncryption, TamperedEntryThrows) {
  TempFile tmp("tamper");
  {
    FileSecretStore store{tmp.path, provider("pw")};
    store.set("jira", "secret");
  }
  // Flip a byte inside the base64 body of the entry line.
  std::string raw = readRaw(tmp.path);
  raw[raw.size() - 3] = (raw[raw.size() - 3] == 'A') ? 'B' : 'A';
  { std::ofstream(tmp.path, std::ios::binary) << raw; }
  FileSecretStore store{tmp.path, provider("pw")};
  EXPECT_THROW(store.get("jira"), std::runtime_error);
}

TEST(FileEncryption, MigratesLegacyPlaintextOnSet) {
  TempFile tmp("migrate");
  // Seed a legacy plaintext file with the plaintext-mode store.
  {
    FileSecretStore legacy{tmp.path};
    legacy.set("old", "legacy-value");
  }
  EXPECT_FALSE(keyward::is_encrypted_file(readRaw(tmp.path)));

  FileSecretStore store{tmp.path, provider("pw")};
  EXPECT_EQ(store.get("old"), "legacy-value");  // read legacy without migrating
  store.set("new", "fresh");                    // this triggers migration
  const std::string raw = readRaw(tmp.path);
  EXPECT_TRUE(keyward::is_encrypted_file(raw));            // now encrypted
  EXPECT_EQ(raw.find("legacy-value"), std::string::npos);  // old value re-sealed
  EXPECT_EQ(store.get("old"), "legacy-value");
  EXPECT_EQ(store.get("new"), "fresh");
}

TEST(FileEncryption, EmptyValueRoundTrips) {
  TempFile tmp("empty");
  FileSecretStore store{tmp.path, provider("pw")};
  store.set("k", "");
  auto v = store.get("k");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "");
}
