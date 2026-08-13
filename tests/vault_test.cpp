// Oracle for Task 6 — the Vault facade. Make it green by implementing
// Vault::save / Vault::load in include/keyward/vault.hpp. Don't edit this file.
#include "keyward/vault.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyward/schema.hpp"
#include "keyward/secret_store.hpp"

namespace {

// A hermetic in-memory SecretStore so tests never touch the real keychain.
class InMemoryStore : public keyward::SecretStore {
 public:
  std::optional<std::string> get(const std::string& name) override {
    auto it = data_.find(name);
    if (it == data_.end()) return std::nullopt;
    return it->second;
  }
  void set(const std::string& name, const std::string& value) override { data_[name] = value; }
  void remove(const std::string& name) override { data_.erase(name); }
  std::vector<std::string> list() override {
    std::vector<std::string> names;
    for (const auto& [k, v] : data_) names.push_back(k);
    return names;
  }
  std::string location() const override { return "in-memory"; }

  std::map<std::string, std::string> data_;  // public so a test can seed/inspect it
};

struct DemoCred {
  std::string email;
  std::string url;
  std::string token;
  bool operator==(const DemoCred&) const = default;

  static keyward::Schema<DemoCred> schema() {
    return {
        {"email", &DemoCred::email},
        {"url", &DemoCred::url},
        {"token", &DemoCred::token, keyward::Sensitive},
    };
  }
};

keyward::Vault make_vault() { return keyward::Vault{std::make_unique<InMemoryStore>()}; }

}  // namespace

TEST(Vault, SaveThenLoadRoundTrips) {
  auto vault = make_vault();
  DemoCred in{"a@b.com", "https://x", "tok"};
  vault.save("jira", in);
  auto out = vault.load<DemoCred>("jira");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, in);
}

TEST(Vault, HasReflectsPresence) {
  auto vault = make_vault();
  EXPECT_FALSE(vault.has("jira"));
  vault.save("jira", DemoCred{"e", "u", "t"});
  EXPECT_TRUE(vault.has("jira"));
}

TEST(Vault, LoadMissingIsNullopt) {
  auto vault = make_vault();
  EXPECT_FALSE(vault.load<DemoCred>("never-saved").has_value());
}

TEST(Vault, RemoveDeletes) {
  auto vault = make_vault();
  vault.save("jira", DemoCred{"e", "u", "t"});
  vault.remove("jira");
  EXPECT_FALSE(vault.has("jira"));
  EXPECT_FALSE(vault.load<DemoCred>("jira").has_value());
}

TEST(Vault, SaveOverwrites) {
  auto vault = make_vault();
  vault.save("jira", DemoCred{"old", "u", "t"});
  vault.save("jira", DemoCred{"new", "u2", "t2"});
  auto out = vault.load<DemoCred>("jira");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (DemoCred{"new", "u2", "t2"}));
}

TEST(Vault, ListsSavedServices) {
  auto vault = make_vault();
  vault.save("jira", DemoCred{"e", "u", "t"});
  vault.save("github", DemoCred{"e2", "u2", "t2"});
  const std::vector<std::string> names = vault.list();
  EXPECT_EQ(names.size(), 2u);
  EXPECT_NE(std::find(names.begin(), names.end(), "jira"), names.end());
  EXPECT_NE(std::find(names.begin(), names.end(), "github"), names.end());
}

TEST(Vault, LoadCorruptBytesIsNullopt) {
  auto store = std::make_unique<InMemoryStore>();
  InMemoryStore* raw = store.get();
  keyward::Vault vault{std::move(store)};
  raw->set("jira", "not a valid record blob");  // seed garbage under the service
  EXPECT_FALSE(vault.load<DemoCred>("jira").has_value());
}
