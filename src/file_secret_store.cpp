#include "keyward/file_secret_store.hpp"

#include <fstream>
#include <stdexcept>
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

void writeAll(const fs::path& p, const std::vector<std::pair<std::string, std::string>>& kv) {
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  fs::permissions(p.parent_path(), fs::perms::owner_all, fs::perm_options::replace, ec);  // 0700
  {
    std::ofstream out(p, std::ios::trunc);
    if (!out) throw std::runtime_error("cannot write " + p.string());
    for (const auto& [k, v] : kv) out << k << "=" << v << "\n";
  }
#if defined(_WIN32)
  // A real owner-only DACL — the 0600 attribute is not access control here. Fail
  // closed: if we can't lock the file down, delete it rather than leave a
  // world-readable secret behind.
  try {
    restrictToOwnerWin(p);
  } catch (...) {
    fs::remove(p, ec);
    throw;
  }
#else
  fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write,  // 0600
                  fs::perm_options::replace, ec);
#endif
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
