#include "keyward/file_secret_store.hpp"

#include <fstream>
#include <stdexcept>

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

std::string trimTrailing(std::string v) {
  while (!v.empty() &&
         (v.back() == '\r' || v.back() == '\n' || v.back() == ' ' || v.back() == '\t'))
    v.pop_back();
  return v;
}

// Read the file as ordered NAME=value pairs (order preserved on rewrite).
std::vector<std::pair<std::string, std::string>> readAll(const fs::path& p) {
  std::vector<std::pair<std::string, std::string>> out;
  std::ifstream in(p);
  std::string line;
  while (std::getline(in, line)) {
    const auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    out.emplace_back(line.substr(0, eq), trimTrailing(line.substr(eq + 1)));
  }
  return out;
}

// Serialize the pairs once, into storage that zeroes itself. The buffer holds
// every secret in the store, so it must not be left in freed heap.
SecureString serialize(const std::vector<std::pair<std::string, std::string>>& kv) {
  SecureString out;
  for (const auto& [k, v] : kv) {
    out.append(k.begin(), k.end());
    out.push_back('=');
    out.append(v.begin(), v.end());
    out.push_back('\n');
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

}  // namespace

FileSecretStore::FileSecretStore(fs::path path) : path_(std::move(path)) {}

std::optional<std::string> FileSecretStore::get(const std::string& name) {
  for (const auto& [k, v] : readAll(path_))
    if (k == name && !v.empty()) return v;
  return std::nullopt;
}

void FileSecretStore::set(const std::string& name, std::string_view value) {
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
}

void FileSecretStore::remove(const std::string& name) {
  std::vector<std::pair<std::string, std::string>> out;
  for (auto& e : readAll(path_))
    if (e.first != name) out.push_back(std::move(e));
  writeAll(path_, out);
}

std::vector<std::string> FileSecretStore::list() {
  std::vector<std::string> names;
  for (const auto& [k, v] : readAll(path_))
    if (!v.empty()) names.push_back(k);  // empty value == absent, matching get()
  return names;
}

}  // namespace keyward
