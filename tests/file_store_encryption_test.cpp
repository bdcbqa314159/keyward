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
#include "keyward/schema.hpp"
#include "keyward/vault.hpp"

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

void writeRaw(const fs::path& p, const std::string& s) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  out.write(s.data(), static_cast<std::streamsize>(s.size()));
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

// Migration is now OPT-IN (allow_plaintext_migration=true) — reading/migrating a
// legacy plaintext file is only done when the caller explicitly trusts it.
TEST(FileEncryption, MigratesLegacyPlaintextOnSetWhenOptedIn) {
  TempFile tmp("migrate");
  // Seed a legacy plaintext file with the plaintext-mode store.
  {
    FileSecretStore legacy{tmp.path};
    legacy.set("old", "legacy-value");
  }
  EXPECT_FALSE(keyward::is_encrypted_file(readRaw(tmp.path)));

  FileSecretStore store{tmp.path, provider("pw"), /*allow_plaintext_migration=*/true};
  EXPECT_EQ(store.get("old"), "legacy-value");  // read legacy without migrating
  store.set("new", "fresh");                    // this triggers migration
  const std::string raw = readRaw(tmp.path);
  EXPECT_TRUE(keyward::is_encrypted_file(raw));            // now encrypted
  EXPECT_EQ(raw.find("legacy-value"), std::string::npos);  // old value re-sealed
  EXPECT_EQ(store.get("old"), "legacy-value");
  EXPECT_EQ(store.get("new"), "fresh");
}

// --- F1: format-downgrade / plaintext-injection must fail closed by default ---

// An encrypted store must NOT silently trust a plaintext-format file dropped in
// by someone with file-write access (a sync folder, a restored backup).
TEST(FileEncryption, RejectsPlaintextFormatWhenEncryptionConfigured) {
  TempFile tmp("inject");
  {
    FileSecretStore s{tmp.path, provider("pw")};
    s.set("token", "REAL");
  }
  ASSERT_TRUE(keyward::is_encrypted_file(readRaw(tmp.path)));

  writeRaw(tmp.path, "token=EVIL-INJECTED\n");  // attacker's plaintext, no magic line

  FileSecretStore reopened{tmp.path, provider("pw")};
  EXPECT_THROW(reopened.get("token"), std::runtime_error);  // fail closed, never the injected bytes
}

// The injection must not survive being laundered into an authentic encrypted
// entry by the next legitimate write.
TEST(FileEncryption, DoesNotLaunderInjectedPlaintextOnNextSet) {
  TempFile tmp("launder");
  {
    FileSecretStore s{tmp.path, provider("pw")};
    s.set("token", "REAL");
  }
  writeRaw(tmp.path, "token=EVIL-INJECTED\napi_key=EVIL2\n");

  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_ANY_THROW(s.set("unrelated", "x"));  // must not re-seal attacker plaintext
  FileSecretStore reopened{tmp.path, provider("pw")};
  EXPECT_ANY_THROW((void)reopened.get("token"));
}

// A corrupted magic line (bit-flip, not a full replacement) must fail closed too,
// not fall through and return the base64 ciphertext body as the value.
TEST(FileEncryption, CorruptMagicLineFailsClosed) {
  TempFile tmp("badmagic");
  {
    FileSecretStore s{tmp.path, provider("pw")};
    s.set("token", "REAL");
  }
  std::string raw = readRaw(tmp.path);
  raw[0] = 'X';  // "keyward-file-v1" -> "Xeyward-file-v1"
  writeRaw(tmp.path, raw);

  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_THROW(s.get("token"), std::runtime_error);
}

// The downgrade must not poison the keyless operations either.
TEST(FileEncryption, DowngradeDoesNotPoisonListOrRemove) {
  TempFile tmp("breadth");
  {
    FileSecretStore s{tmp.path, provider("pw")};
    s.set("real", "R");
  }
  writeRaw(tmp.path, "injected=ZZZ\n");

  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_THROW(s.list(), std::runtime_error);              // not a list of planted names
  EXPECT_THROW(s.remove("whatever"), std::runtime_error);  // must not rewrite as plaintext
}

TEST(FileEncryption, EmptyValueRoundTrips) {
  TempFile tmp("empty");
  FileSecretStore store{tmp.path, provider("pw")};
  store.set("k", "");
  auto v = store.get("k");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, "");
}

// --- F6: cached key must not be reused for a mismatched salt ---

// After the on-disk salt changes underneath a live store, a set() must re-derive
// for the file's current salt rather than seal the new entry under the stale
// cached key (which would write a file where the new entry can't decrypt). Same
// passphrase throughout; only the salt (and thus the correct key) differs.
TEST(FileEncryption, DoesNotSealUnderStaleKeyAfterSaltChange) {
  TempFile a("f6a"), b("f6b");
  // Two encrypted files, SAME passphrase, DIFFERENT (random) salts.
  {
    FileSecretStore s{b.path, provider("pw")};
    s.set("z", "from-b");
  }
  const std::string bFile = readRaw(b.path);

  FileSecretStore s{a.path, provider("pw")};
  s.set("x", "from-a");     // caches the key for a's salt
  writeRaw(a.path, bFile);  // swap in b's file: same pw, different salt
  s.set("y", "2");          // must re-derive for b's salt, not seal under a's stale key

  FileSecretStore reopened{a.path, provider("pw")};
  EXPECT_EQ(reopened.get("y"), "2");       // new entry decrypts (RED before the fix)
  EXPECT_EQ(reopened.get("z"), "from-b");  // b's original entry still decrypts
}

// --- F5: reject a malformed salt length before deriving ---

// A crafted file with a wrong-length (here empty) salt must be rejected up front,
// not fed into derive_key — fail closed, and never crash/abort.
TEST(FileEncryption, RejectsMalformedSaltLength) {
  TempFile tmp("badsalt");
  writeRaw(tmp.path, "keyward-file-v1\nsalt=\ntoken=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n");
  FileSecretStore s{tmp.path, provider("pw")};
  EXPECT_THROW(s.get("token"), std::runtime_error);
}

// --- F2: the plaintext tier must be binary-safe (Vault stores binary blobs) ---

TEST(FilePlaintext, RoundTripsBinaryValuesLosslessly) {
  TempFile tmp("bin");
  FileSecretStore s{tmp.path};  // plaintext mode (no provider)

  const std::string with_newline = "a\nb";         // embedded 0x0a — old getline truncated this
  const std::string with_trailing_ws = "secret ";  // old trimTrailing ate this
  const std::string with_nul = std::string("x\0y", 3);
  s.set("k1", with_newline);
  s.set("k2", with_trailing_ws);
  s.set("k3", with_nul);

  EXPECT_EQ(s.get("k1"), with_newline);
  EXPECT_EQ(s.get("k2"), with_trailing_ws);
  EXPECT_EQ(s.get("k3"), with_nul);
}

namespace {
struct BinCred {
  std::string user;
  std::string token;
  bool operator==(const BinCred&) const = default;
  static keyward::Schema<BinCred> schema() {
    return {{"user", &BinCred::user}, {"token", &BinCred::token, keyward::Sensitive}};
  }
};
}  // namespace

// End-to-end: a Vault record whose serialized blob contains 0x0a must survive a
// save/load through the plaintext file tier (the sole tier on no-vault hosts).
TEST(FilePlaintext, VaultRecordSurvivesPlaintextTier) {
  TempFile tmp("vaultbin");
  keyward::Vault v{std::make_unique<FileSecretStore>(tmp.path)};
  const BinCred in{"u", "tok\nen-value"};  // newline in a field value forces 0x0a in the blob
  v.save("svc", in);
  const auto out = v.load<BinCred>("svc");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}

// A legacy raw plaintext file (no magic) is still readable, then upgraded to v1
// on the next write.
TEST(FilePlaintext, ReadsLegacyRawThenUpgrades) {
  TempFile tmp("legacyraw");
  writeRaw(tmp.path, "simple=value\nother=thing\n");  // old raw format, no magic line
  FileSecretStore s{tmp.path};
  EXPECT_EQ(s.get("simple"), "value");
  EXPECT_EQ(s.get("other"), "thing");
  s.set("new", "x");                                              // rewrites in v1
  EXPECT_EQ(readRaw(tmp.path).rfind("keyward-plain-v1", 0), 0u);  // now v1
  EXPECT_EQ(s.get("simple"), "value");                            // still readable
}
