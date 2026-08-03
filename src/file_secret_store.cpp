#include "keyward/file_secret_store.hpp"

#include <fstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace keyward {
namespace {

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
  fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write,  // 0600
                  fs::perm_options::replace, ec);
}

}  // namespace

FileSecretStore::FileSecretStore(fs::path path) : path_(std::move(path)) {}

std::optional<std::string> FileSecretStore::get(const std::string& name) {
  for (const auto& [k, v] : readAll(path_))
    if (k == name && !v.empty()) return v;
  return std::nullopt;
}

void FileSecretStore::set(const std::string& name, const std::string& value) {
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

}  // namespace keyward
