// Task 7 — Prompter protocol + Vault::ensure/revise. Driven by a scriptable
// fake prompter, so nothing here touches a terminal or the real keychain.
#include "keyward/prompter.hpp"

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "keyward/schema.hpp"
#include "keyward/secret_store.hpp"
#include "keyward/vault.hpp"

namespace {

class InMemoryStore : public keyward::SecretStore {
 public:
  std::optional<std::string> get(const std::string& n) override {
    auto it = data_.find(n);
    if (it == data_.end()) return std::nullopt;
    return it->second;
  }
  void set(const std::string& n, std::string_view v) override { data_[n] = v; }
  void remove(const std::string& n) override { data_.erase(n); }
  std::string location() const override { return "in-memory"; }
  std::map<std::string, std::string> data_;
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

// Scriptable prompter: canned answers by field name, optional cancel, and it
// records what the SDK asked (fields as handed in, before filling).
class FakePrompter : public keyward::Prompter {
 public:
  std::map<std::string, std::string> answers;
  bool cancel = false;
  int calls = 0;
  keyward::PromptReason last_reason{};
  std::vector<keyward::PromptField> asked;

  bool collect(std::string_view, keyward::PromptReason reason,
               std::vector<keyward::PromptField>& fields) override {
    ++calls;
    last_reason = reason;
    asked = fields;  // snapshot the prefilled state the SDK passed in
    if (cancel) return false;
    for (auto& f : fields) {
      auto it = answers.find(f.name);
      if (it != answers.end()) f.value = it->second;
    }
    return true;
  }
};

keyward::Vault make_vault() { return keyward::Vault{std::make_unique<InMemoryStore>()}; }

using keyward::PromptReason;

}  // namespace

TEST(Ensure, MissingPromptsCreateAndSaves) {
  auto vault = make_vault();
  FakePrompter p;
  p.answers = {{"email", "a@b.com"}, {"url", "https://x"}, {"token", "tok"}};
  auto got = vault.ensure<DemoCred>("jira", p);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(*got, (DemoCred{"a@b.com", "https://x", "tok"}));
  EXPECT_EQ(p.calls, 1);
  EXPECT_EQ(p.last_reason, PromptReason::Missing);
  EXPECT_TRUE(vault.has("jira"));  // persisted
  EXPECT_EQ(vault.load<DemoCred>("jira"), got);
}

TEST(Ensure, PresentLoadsWithoutPrompting) {
  auto vault = make_vault();
  vault.save("jira", DemoCred{"e", "u", "t"});
  FakePrompter p;
  auto got = vault.ensure<DemoCred>("jira", p);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(*got, (DemoCred{"e", "u", "t"}));
  EXPECT_EQ(p.calls, 0);  // never prompted
}

TEST(Ensure, CancelSavesNothing) {
  auto vault = make_vault();
  FakePrompter p;
  p.cancel = true;
  auto got = vault.ensure<DemoCred>("jira", p);
  EXPECT_FALSE(got.has_value());
  EXPECT_FALSE(vault.has("jira"));
}

TEST(Ensure, CreatePrefillIsEmpty) {
  auto vault = make_vault();
  FakePrompter p;
  p.answers = {{"email", "e"}, {"url", "u"}, {"token", "t"}};
  vault.ensure<DemoCred>("jira", p);
  ASSERT_EQ(p.asked.size(), 3u);
  for (const auto& f : p.asked) EXPECT_EQ(f.value, "");  // nothing pre-filled on create
}

TEST(Prompter, SensitiveFlagComesFromSchema) {
  auto vault = make_vault();
  FakePrompter p;
  p.answers = {{"email", "e"}, {"url", "u"}, {"token", "t"}};
  vault.ensure<DemoCred>("jira", p);
  std::map<std::string, bool> sens;
  for (const auto& f : p.asked) sens[f.name] = f.sensitive;
  EXPECT_TRUE(sens["token"]);  // marked keyward::Sensitive
  EXPECT_FALSE(sens["email"]);
  EXPECT_FALSE(sens["url"]);
}

TEST(Revise, InvalidPrefillsCurrentThenSaves) {
  auto vault = make_vault();
  vault.save("jira", DemoCred{"e", "u", "old"});
  FakePrompter p;
  p.answers = {{"token", "new"}};  // user edits only the token
  auto got = vault.revise<DemoCred>("jira", p);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(p.last_reason, PromptReason::Invalid);
  std::map<std::string, std::string> pre;
  for (const auto& f : p.asked) pre[f.name] = f.value;
  EXPECT_EQ(pre["email"], "e");  // current values pre-filled
  EXPECT_EQ(pre["url"], "u");
  EXPECT_EQ(pre["token"], "old");
  EXPECT_EQ(*got, (DemoCred{"e", "u", "new"}));  // kept e/u, updated token
  EXPECT_EQ(vault.load<DemoCred>("jira"), got);
}
