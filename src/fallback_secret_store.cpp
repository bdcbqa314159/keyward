#include "keyward/fallback_secret_store.hpp"

#include <algorithm>
#include <exception>
#include <stdexcept>
#include <utility>

namespace keyward {

FallbackSecretStore::FallbackSecretStore(std::unique_ptr<SecretStore> primary,
                                         std::unique_ptr<SecretStore> fallback)
    : primary_(std::move(primary)), fallback_(std::move(fallback)) {
  if (!primary_ || !fallback_)
    throw std::invalid_argument("keyward: FallbackSecretStore requires two non-null tiers");
}

std::optional<std::string> FallbackSecretStore::get(const std::string& name) {
  if (auto v = primary_->get(name)) return v;
  return fallback_->get(name);
}

void FallbackSecretStore::set(const std::string& name, std::string_view value) {
  primary_->set(name, value);
  // Migration is MOVING, not copying: evict any stale/legacy copy from the
  // fallback so a later primary miss can't resurrect a revoked/pre-rotation
  // value. Only touch the fallback if it actually holds the name (so we don't
  // create a spurious plaintext file just to remove from it).
  if (fallback_->get(name).has_value()) fallback_->remove(name);
}

void FallbackSecretStore::remove(const std::string& name) {
  // Delete from BOTH tiers even if one throws — never leave the weaker tier
  // holding a value the caller deleted. Remove from the weaker tier first, then
  // the primary, and rethrow the first error.
  std::exception_ptr err;
  try {
    if (fallback_->get(name).has_value()) fallback_->remove(name);
  } catch (...) {
    err = std::current_exception();
  }
  try {
    primary_->remove(name);
  } catch (...) {
    if (!err) err = std::current_exception();
  }
  if (err) std::rethrow_exception(err);
}

std::vector<std::string> FallbackSecretStore::list() {
  // Union both tiers' names (de-duplicated); propagate — never swallow — either
  // tier's failure, since a partial list would violate the contract.
  std::vector<std::string> names = primary_->list();
  for (const std::string& n : fallback_->list())
    if (std::find(names.begin(), names.end(), n) == names.end()) names.push_back(n);
  return names;
}

std::string FallbackSecretStore::location() const {
  return primary_->location() + " (fallback: " + fallback_->location() + ")";
}

}  // namespace keyward
