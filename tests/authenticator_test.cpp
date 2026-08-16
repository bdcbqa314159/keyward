// Vault's access-time gate. Driven by a fake authenticator (no biometric /
// passphrase), so the semantics are testable without any user interaction.
#include "keyward/authenticator.hpp"

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>
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
  void set(const std::string& n, const std::string& v) override { data_[n] = v; }
  void remove(const std::string& n) override { data_.erase(n); }
  std::string location() const override { return "in-memory"; }
  std::vector<std::string> list() override {
    std::vector<std::string> out;
    for (auto& [k, v] : data_) out.push_back(k);
    return out;
  }
  std::map<std::string, std::string> data_;
};

struct DemoCred {
  std::string email;
  std::string url;
  std::string token;
  bool operator==(const DemoCred&) const = default;
  static keyward::Schema<DemoCred> schema() {
    return {{"email", &DemoCred::email},
            {"url", &DemoCred::url},
            {"token", &DemoCred::token, keyward::Sensitive}};
  }
};

// A scriptable gate: return a chosen Authorization, count consultations.
class FakeAuth : public keyward::Authenticator {
 public:
  keyward::Authorization result = keyward::Authorization::Allowed;
  int calls = 0;
  keyward::Authorization authorize(std::string_view, std::string_view) override {
    ++calls;
    return result;
  }
};

class FakePrompter : public keyward::Prompter {
 public:
  std::map<std::string, std::string> answers;
  int calls = 0;
  bool collect(std::string_view, keyward::PromptReason,
               std::vector<keyward::PromptField>& fields) override {
    ++calls;
    for (auto& f : fields) {
      auto it = answers.find(f.name);
      if (it != answers.end()) f.value = it->second;
    }
    return true;
  }
};

using keyward::Authorization;
using keyward::Vault;

}  // namespace

TEST(Authenticator, NoAuthAllowsByDefault) {
  Vault vault{std::make_unique<InMemoryStore>()};  // default NoAuth
  vault.save("jira", DemoCred{"e", "u", "t"});
  auto out = vault.load<DemoCred>("jira");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (DemoCred{"e", "u", "t"}));
}

TEST(Authenticator, DeniedLoadReturnsNullopt) {
  auto authp = std::make_unique<FakeAuth>();
  FakeAuth* auth = authp.get();
  Vault vault{std::make_unique<InMemoryStore>(), std::move(authp)};
  vault.save("jira", DemoCred{"e", "u", "t"});  // save is not gated
  auth->result = Authorization::Denied;
  EXPECT_FALSE(vault.load<DemoCred>("jira").has_value());
  EXPECT_GE(auth->calls, 1);  // the gate was consulted
}

TEST(Authenticator, AllowedLoadReleases) {
  auto authp = std::make_unique<FakeAuth>();  // Allowed by default
  FakeAuth* auth = authp.get();
  Vault vault{std::make_unique<InMemoryStore>(), std::move(authp)};
  vault.save("jira", DemoCred{"e", "u", "t"});
  auto out = vault.load<DemoCred>("jira");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (DemoCred{"e", "u", "t"}));
  EXPECT_GE(auth->calls, 1);
}

TEST(Authenticator, EnsureDeniedDoesNotReprompt) {
  auto authp = std::make_unique<FakeAuth>();
  FakeAuth* auth = authp.get();
  Vault vault{std::make_unique<InMemoryStore>(), std::move(authp)};
  vault.save("jira", DemoCred{"e", "u", "t"});
  auth->result = Authorization::Denied;
  FakePrompter p;
  EXPECT_FALSE(vault.ensure<DemoCred>("jira", p).has_value());
  EXPECT_EQ(p.calls, 0);  // present-but-denied is a hard stop, NOT a re-entry prompt
}

TEST(Authenticator, EnsurePresentAllowedLoadsWithoutPrompt) {
  Vault vault{std::make_unique<InMemoryStore>()};  // NoAuth
  vault.save("jira", DemoCred{"e", "u", "t"});
  FakePrompter p;
  auto out = vault.ensure<DemoCred>("jira", p);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (DemoCred{"e", "u", "t"}));
  EXPECT_EQ(p.calls, 0);
}

TEST(Authenticator, EnsureMissingPromptsWithoutGating) {
  auto authp = std::make_unique<FakeAuth>();
  FakeAuth* auth = authp.get();
  Vault vault{std::make_unique<InMemoryStore>(), std::move(authp)};
  auth->result = Authorization::Denied;  // even a denying gate...
  FakePrompter p;
  p.answers = {{"email", "e"}, {"url", "u"}, {"token", "t"}};
  auto out = vault.ensure<DemoCred>("newsvc", p);  // ...missing -> creating is not gated
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(p.calls, 1);
  EXPECT_EQ(auth->calls, 0);  // nothing to release, so the gate is never consulted
}
