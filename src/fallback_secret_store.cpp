#include "keyward/fallback_secret_store.hpp"

#include <utility>

namespace keyward {

FallbackSecretStore::FallbackSecretStore(std::unique_ptr<SecretStore> primary,
                                         std::unique_ptr<SecretStore> fallback)
    : primary_(std::move(primary)), fallback_(std::move(fallback)) {}

std::optional<std::string> FallbackSecretStore::get(const std::string& name) {
  if (auto v = primary_->get(name)) return v;
  return fallback_->get(name);
}

void FallbackSecretStore::set(const std::string& name, std::string_view value) {
  primary_->set(name, value);  // migrates here; the fallback copy just goes stale
}

void FallbackSecretStore::remove(const std::string& name) {
  primary_->remove(name);
  fallback_->remove(name);
}

std::string FallbackSecretStore::location() const {
  return primary_->location() + " (fallback: " + fallback_->location() + ")";
}

}  // namespace keyward
