// FallbackSecretStore compose semantics: evict-on-set (H1), remove-reaches-both
// (H2), list-unions-both (M6), reject-null-tiers (L8). In-memory tiers — no
// backend, no I/O.
#include "keyward/fallback_secret_store.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "keyward/secret_store.hpp"

namespace {

class InMemoryStore : public keyward::SecretStore {
 public:
  std::optional<std::string> get(const std::string& n) override {
    auto it = data_.find(n);
    return it == data_.end() ? std::nullopt : std::optional<std::string>(it->second);
  }
  void set(const std::string& n, std::string_view v) override { data_[n] = std::string(v); }
  void remove(const std::string& n) override { data_.erase(n); }
  std::vector<std::string> list() override {
    std::vector<std::string> out;
    for (auto& [k, v] : data_) out.push_back(k);
    return out;
  }
  std::string location() const override { return "mem"; }
  std::map<std::string, std::string> data_;
};

// remove() throws (e.g. a locked keyring), to prove the other tier is still hit.
class ThrowOnRemoveStore : public InMemoryStore {
 public:
  void remove(const std::string&) override { throw std::runtime_error("locked"); }
};

}  // namespace

using keyward::FallbackSecretStore;

TEST(FallbackCompose, RejectsNullTiers) {  // L8
  EXPECT_THROW(FallbackSecretStore(nullptr, std::make_unique<InMemoryStore>()),
               std::invalid_argument);
  EXPECT_THROW(FallbackSecretStore(std::make_unique<InMemoryStore>(), nullptr),
               std::invalid_argument);
}

TEST(FallbackCompose, SetEvictsStaleFallbackCopy) {  // H1
  auto p = std::make_unique<InMemoryStore>();
  auto f = std::make_unique<InMemoryStore>();
  InMemoryStore* pr = p.get();
  InMemoryStore* fb = f.get();
  fb->data_["token"] = "OLD-PLAINTEXT";  // legacy copy in the fallback
  FallbackSecretStore store{std::move(p), std::move(f)};
  store.set("token", "ROTATED");  // rotate via the primary
  EXPECT_EQ(pr->data_["token"], "ROTATED");
  EXPECT_EQ(fb->data_.count("token"), 0u);   // stale copy evicted — no resurrection
  EXPECT_EQ(store.get("token"), "ROTATED");  // a fallback read can't serve the old value
}

TEST(FallbackCompose, RemoveReachesFallbackEvenIfPrimaryThrows) {  // H2
  auto p = std::make_unique<ThrowOnRemoveStore>();
  auto f = std::make_unique<InMemoryStore>();
  InMemoryStore* fb = f.get();
  fb->data_["token"] = "PLAINTEXT-COPY";
  FallbackSecretStore store{std::move(p), std::move(f)};
  EXPECT_THROW(store.remove("token"), std::runtime_error);  // primary's error propagates
  EXPECT_EQ(fb->data_.count("token"), 0u);                  // but the fallback copy is gone
}

TEST(FallbackCompose, ListUnionsBothTiers) {  // M6
  auto p = std::make_unique<InMemoryStore>();
  auto f = std::make_unique<InMemoryStore>();
  p->data_["a"] = "1";
  p->data_["shared"] = "p";
  f->data_["b"] = "2";
  f->data_["shared"] = "f";
  FallbackSecretStore store{std::move(p), std::move(f)};
  auto names = store.list();
  std::sort(names.begin(), names.end());
  EXPECT_EQ(names, (std::vector<std::string>{"a", "b", "shared"}));  // union, de-duplicated
}

TEST(FallbackCompose, GetPrefersPrimaryThenFallback) {
  auto p = std::make_unique<InMemoryStore>();
  auto f = std::make_unique<InMemoryStore>();
  p->data_["only-p"] = "P";
  f->data_["only-f"] = "F";
  f->data_["only-p"] = "SHOULD-NOT-WIN";
  FallbackSecretStore store{std::move(p), std::move(f)};
  EXPECT_EQ(store.get("only-p"), "P");  // primary wins
  EXPECT_EQ(store.get("only-f"), "F");  // falls through
  EXPECT_FALSE(store.get("missing").has_value());
}
