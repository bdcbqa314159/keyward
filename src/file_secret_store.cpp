#include "keyward/file_secret_store.hpp"

#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>

#include "keyward/base64.hpp"                 // base64_encode/decode (binary-safe plaintext values)
#include "keyward/crypto_primitives.hpp"      // aead_seal/aead_open, kNonceSize, kSaltSize
#include "keyward/encrypted_file_format.hpp"  // EncryptedFile, parse/format, is_encrypted_file
#include "keyward/random.hpp"                 // random_bytes
#include "keyward/secure_memory.hpp"          // secure_zero
#include "keyward/secure_string.hpp"

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#endif
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
// clang-format off
#include <windows.h>
#include <aclapi.h>
// clang-format on
#endif

namespace fs = std::filesystem;

namespace keyward {
namespace {

#if defined(_WIN32)
// Replace a file's DACL with a single owner-only ACE, and mark it PROTECTED so
// inherited ACEs (which typically grant the Users group) are stripped. On
// Windows, std::filesystem::permissions cannot express this — 0600 there only
// toggles the read-only *attribute*, which is not access control. Throws on any
// failure so the caller can fail closed rather than leave a readable secret.
void restrictToOwnerWin(const fs::path& p) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    throw std::runtime_error("keyward: OpenProcessToken failed");
  DWORD len = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &len);  // size probe
  std::vector<BYTE> buf(len);
  const BOOL ok = GetTokenInformation(token, TokenUser, buf.data(), len, &len);
  CloseHandle(token);
  if (!ok) throw std::runtime_error("keyward: GetTokenInformation failed");
  PSID userSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;

  EXPLICIT_ACCESSW ea = {};
  ea.grfAccessPermissions = GENERIC_ALL;
  ea.grfAccessMode = SET_ACCESS;
  ea.grfInheritance = NO_INHERITANCE;
  ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(userSid);

  PACL acl = nullptr;
  if (SetEntriesInAclW(1, &ea, nullptr, &acl) != ERROR_SUCCESS)
    throw std::runtime_error("keyward: SetEntriesInAcl failed");

  const std::wstring wpath = p.wstring();
  const DWORD rc =
      SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, acl, nullptr);
  if (acl != nullptr) LocalFree(acl);
  if (rc != ERROR_SUCCESS)
    throw std::runtime_error("keyward: SetNamedSecurityInfo failed (error " + std::to_string(rc) +
                             ")");
}
#endif  // _WIN32

constexpr std::string_view kPlainMagic = "keyward-plain-v1";

std::string trimTrailing(std::string v) {
  while (!v.empty() &&
         (v.back() == '\r' || v.back() == '\n' || v.back() == ' ' || v.back() == '\t'))
    v.pop_back();
  return v;
}

// Read the plaintext file as ordered NAME=value pairs. The v1 format
// base64-encodes each value so arbitrary bytes survive the line-based file — a
// Vault blob is length-prefixed binary that routinely contains 0x0a (a newline)
// or trailing whitespace, which the old raw `getline`/`trimTrailing` path
// silently corrupted. A file without the magic line is a legacy raw file, read
// best-effort (and rewritten to v1 on the next write).
std::vector<std::pair<std::string, std::string>> readAll(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::vector<std::pair<std::string, std::string>> out;
  if (text.empty()) return out;

  std::string_view rest = text;
  auto nextLine = [&rest]() -> std::string_view {
    const std::size_t nl = rest.find('\n');
    std::string_view line = (nl == std::string_view::npos) ? rest : rest.substr(0, nl);
    rest = (nl == std::string_view::npos) ? std::string_view{} : rest.substr(nl + 1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    return line;
  };

  const std::string_view whole = rest;
  const bool v1 = (nextLine() == kPlainMagic);  // consumes the first line
  if (!v1) rest = whole;                        // no magic: first line was legacy data, rewind

  while (!rest.empty()) {
    const std::string_view line = nextLine();
    if (line.empty()) continue;
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) continue;  // skip malformed
    const std::string_view name = line.substr(0, eq);
    const std::string_view val = line.substr(eq + 1);
    if (v1) {
      std::optional<std::string> dec = base64_decode(val);
      if (!dec) continue;  // skip a corrupt entry rather than return garbage
      out.emplace_back(std::string(name), std::move(*dec));
    } else {
      out.emplace_back(std::string(name), trimTrailing(std::string(val)));  // legacy raw
    }
  }
  return out;
}

// Serialize the pairs once, into storage that zeroes itself (holds every secret).
// v1 format: magic line, then NAME=base64(value) so binary values round-trip.
SecureString serialize(const std::vector<std::pair<std::string, std::string>>& kv) {
  SecureString out;
  out.append(kPlainMagic.begin(), kPlainMagic.end());
  out.push_back('\n');
  for (const auto& [k, v] : kv) {
    out.append(k.begin(), k.end());
    out.push_back('=');
    std::string enc = base64_encode(v);
    out.append(enc.begin(), enc.end());
    out.push_back('\n');
    secure_zero(enc.data(), enc.size());  // wipe the transient encoded value
  }
  return out;
}

// Replace `p` atomically: write a fresh temp file beside it, flush it to disk,
// then rename over the target.
//
// The old code opened the real file with std::ios::trunc and wrote into it. Two
// things were wrong with that. A crash, OOM kill or power loss between the
// truncate and the last write left the file EMPTY OR PARTIAL — losing every
// credential in it, not just the one being written — and two writers racing
// produced an interleaved file. rename(2) is atomic within a filesystem, so a
// reader or a crash now sees either the whole old file or the whole new one.
//
// It also closes a permissions window: the temp file is owner-only from the
// moment it exists, where the old path created the real file under the ambient
// umask and only chmod'd it afterwards.
void writeAtomically(const fs::path& p, const SecureString& content) {
#if defined(_WIN32)
  const fs::path tmp = p.string() + ".kwtmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + tmp.string());
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("cannot write " + tmp.string());
  }
  std::error_code ec;
  try {
    // Lock it down BEFORE it becomes the real file, so the credentials file is
    // never briefly readable by others.
    restrictToOwnerWin(tmp);
    // ReplaceExisting because rename over an existing file fails on Windows;
    // WriteThrough so the move is on disk before we return.
    if (!MoveFileExW(tmp.wstring().c_str(), p.wstring().c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      throw std::runtime_error("cannot replace " + p.string());
    }
  } catch (...) {
    fs::remove(tmp, ec);  // never leave a temp file holding secrets
    throw;
  }
#else
  std::string pattern = p.string() + ".kwtmpXXXXXX";
  std::vector<char> path_buf(pattern.begin(), pattern.end());
  path_buf.push_back('\0');

  // mkstemp creates with 0600 — owner-only from the instant it exists.
  int fd = ::mkstemp(path_buf.data());
  if (fd < 0) throw std::runtime_error("cannot create a temp file beside " + p.string());
  const fs::path tmp(path_buf.data());

  try {
    const char* data = content.data();
    std::size_t left = content.size();
    while (left > 0) {
      const ssize_t n = ::write(fd, data, left);
      if (n < 0) {
        if (errno == EINTR) continue;
        throw std::runtime_error("cannot write " + tmp.string());
      }
      data += n;
      left -= static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) throw std::runtime_error("cannot flush " + tmp.string());
    if (::close(fd) != 0) {
      fd = -1;
      throw std::runtime_error("cannot close " + tmp.string());
    }
    fd = -1;
    if (::rename(tmp.c_str(), p.c_str()) != 0) {
      throw std::runtime_error("cannot replace " + p.string());
    }
  } catch (...) {
    if (fd >= 0) ::close(fd);
    std::error_code ec;
    fs::remove(tmp, ec);  // never leave a temp file holding secrets
    throw;
  }

  // The contents were fsynced, but the directory entry created by rename was
  // not. Without this a power failure can lose the rename itself.
  const int dir_fd = ::open(p.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
#endif
}

void writeAll(const fs::path& p, const std::vector<std::pair<std::string, std::string>>& kv) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  fs::permissions(p.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);  // 0700
  const SecureString content = serialize(kv);
  writeAtomically(p, content);
}

// Read the whole file as text (empty if absent). An encrypted file's contents
// are ciphertext + base64, not secrets, so a plain string is fine here.
std::string readFileText(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return {};
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// Write an encrypted file (magic + salt + base64 sealed entries), reusing the
// same 0700-dir + owner-only + atomic-replace path as the plaintext writer.
void writeEncrypted(const fs::path& p, const EncryptedFile& ef) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  fs::permissions(p.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);  // 0700
  const std::string text = format_encrypted_file(ef);
  writeAtomically(p, SecureString(text.begin(), text.end()));
}

}  // namespace

FileSecretStore::FileSecretStore(fs::path path) : path_(std::move(path)) {}

FileSecretStore::FileSecretStore(fs::path path, std::unique_ptr<KeyProvider> key_provider,
                                 bool allow_plaintext_migration)
    : path_(std::move(path)),
      key_provider_(std::move(key_provider)),
      allow_plaintext_migration_(allow_plaintext_migration) {}

// An encryption-mode store is looking at a present, non-empty file that is NOT
// in the encrypted format. The format was decided from unauthenticated bytes, so
// unless the caller explicitly opted into trusting a legacy plaintext file, this
// is a tamper / format downgrade — refuse it.
void FileSecretStore::guardDowngrade() const {
  if (allow_plaintext_migration_) return;
  throw std::runtime_error(
      "keyward: refusing a non-encrypted file for the encrypted store " + path_.string() +
      " (possible tampering / format downgrade). Only construct with "
      "allow_plaintext_migration=true for a file you trust is a genuine legacy plaintext store.");
}

const Secret& FileSecretStore::ensureKey(std::string_view salt) {
  if (!key_) {
    salt_ = std::string(salt);
    std::optional<Secret> k = key_provider_->unlock(salt_, "unlock " + path_.filename().string());
    if (!k) throw std::runtime_error("keyward: passphrase entry cancelled for " + path_.string());
    key_ = std::move(*k);
  }
  return *key_;
}

// Names in a plaintext file whose value is non-empty (empty value == absent).
namespace {
std::optional<std::string> plaintextGet(const fs::path& p, const std::string& name) {
  for (const auto& [k, v] : readAll(p))
    if (k == name && !v.empty()) return v;
  return std::nullopt;
}
}  // namespace

std::optional<std::string> FileSecretStore::get(const std::string& name) {
  if (!encrypted()) return plaintextGet(path_, name);

  const std::string text = readFileText(path_);
  if (text.empty()) return std::nullopt;
  if (!is_encrypted_file(text)) {
    guardDowngrade();                  // throws unless legacy migration opted-in
    return plaintextGet(path_, name);  // opted-in: read the legacy plaintext file
  }

  std::optional<EncryptedFile> ef = parse_encrypted_file(text);
  if (!ef) throw std::runtime_error("keyward: corrupt encrypted store " + path_.string());
  for (const auto& [k, blob] : ef->entries) {
    if (k != name) continue;
    if (blob.size() < kNonceSize)
      throw std::runtime_error("keyward: truncated entry '" + name + "'");
    ensureKey(ef->salt);
    std::string_view nonce(blob.data(), kNonceSize);
    std::string_view sealed(blob.data() + kNonceSize, blob.size() - kNonceSize);
    std::optional<Secret> pt = aead_open(*key_, nonce, sealed);
    if (!pt)
      throw std::runtime_error("keyward: cannot decrypt '" + name +
                               "' (wrong passphrase or tampered)");
    return std::string(pt->view());
  }
  return std::nullopt;
}

void FileSecretStore::set(const std::string& name, std::string_view value) {
  if (!encrypted()) {
    auto kv = readAll(path_);
    bool found = false;
    for (auto& e : kv)
      if (e.first == name) {
        e.second = value;
        found = true;
        break;
      }
    if (!found) kv.emplace_back(name, value);
    writeAll(path_, kv);
    return;
  }

  const std::string text = readFileText(path_);
  EncryptedFile ef;
  if (!text.empty() && is_encrypted_file(text)) {
    std::optional<EncryptedFile> parsed = parse_encrypted_file(text);
    if (!parsed) throw std::runtime_error("keyward: corrupt encrypted store " + path_.string());
    ef = std::move(*parsed);
    ensureKey(ef.salt);  // keep the file's existing salt so cached key stays valid
  } else if (text.empty()) {
    ef.salt = random_bytes(kSaltSize);  // brand-new file
    ensureKey(ef.salt);
  } else {
    guardDowngrade();  // non-empty, non-encrypted -> throws unless migration opted-in
    ef.salt = random_bytes(kSaltSize);
    ensureKey(ef.salt);
    for (auto& [k, v] : readAll(path_)) {  // opted-in: re-seal every legacy entry under the new key
      std::string nonce = random_bytes(kNonceSize);
      ef.entries.emplace_back(k, nonce + aead_seal(*key_, nonce, v));
      secure_zero(v.data(), v.size());  // wipe the legacy plaintext once re-sealed
    }
  }

  std::string nonce = random_bytes(kNonceSize);
  std::string blob = nonce + aead_seal(*key_, nonce, value);
  bool found = false;
  for (auto& e : ef.entries)
    if (e.first == name) {
      e.second = std::move(blob);
      found = true;
      break;
    }
  if (!found) ef.entries.emplace_back(name, std::move(blob));
  writeEncrypted(path_, ef);
}

void FileSecretStore::remove(const std::string& name) {
  const std::string text = encrypted() ? readFileText(path_) : std::string{};
  if (encrypted() && !text.empty() && is_encrypted_file(text)) {
    // Drop the entry keeping the others' ciphertext untouched — no key needed.
    std::optional<EncryptedFile> ef = parse_encrypted_file(text);
    if (!ef) throw std::runtime_error("keyward: corrupt encrypted store " + path_.string());
    EncryptedFile out;
    out.salt = ef->salt;
    for (auto& e : ef->entries)
      if (e.first != name) out.entries.push_back(std::move(e));
    writeEncrypted(path_, out);
    return;
  }
  // Encryption mode looking at a present, non-encrypted file: refuse the
  // downgrade (unless opted-in) rather than rewriting the store as plaintext.
  if (encrypted() && !text.empty()) guardDowngrade();
  // Plaintext mode, empty file, or an opted-in legacy file: rewrite plaintext.
  std::vector<std::pair<std::string, std::string>> out;
  for (auto& e : readAll(path_))
    if (e.first != name) out.push_back(std::move(e));
  writeAll(path_, out);
}

std::vector<std::string> FileSecretStore::list() {
  if (encrypted()) {
    const std::string text = readFileText(path_);
    if (!text.empty() && is_encrypted_file(text)) {
      std::optional<EncryptedFile> ef = parse_encrypted_file(text);
      if (!ef) throw std::runtime_error("keyward: corrupt encrypted store " + path_.string());
      std::vector<std::string> names;
      for (const auto& [k, blob] : ef->entries) names.push_back(k);  // no key needed
      return names;
    }
    // Present, non-encrypted file under an encrypted store: refuse the downgrade
    // (unless opted-in) rather than enumerating attacker-chosen names.
    if (!text.empty()) guardDowngrade();
  }
  std::vector<std::string> names;
  for (const auto& [k, v] : readAll(path_))
    if (!v.empty()) names.push_back(k);  // empty value == absent, matching get()
  return names;
}

}  // namespace keyward
