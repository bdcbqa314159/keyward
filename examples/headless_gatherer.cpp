// A headless data gatherer: credentials injected by the environment, no prompt,
// no terminal, no user — the shape a cron job, container or CI runner needs.
//
// keyward needs NO changes to support this. The application supplies the ~20
// lines below, which is what the contract intends: keyward owns storage,
// serialization and the platform keychains; the app owns where credentials come
// from when there is nobody to ask.
//
// WHERE THE ENV OVERRIDE BELONGS, and why. It is tempting to write a custom
// SecretStore that returns an env var and chain it in front of the platform one.
// That does not work for typed records, and the reason is worth knowing: the
// SecretStore seam is byte-opaque — its value is an `encode_fields()` blob, which
// is length-prefixed binary containing NUL bytes — and an environment variable is
// a NUL-terminated C string that cannot carry them. (A store-layer overlay is
// fine if you use SecretStore directly for opaque bytes; it is only typed records
// it cannot serve.)
//
// So the override goes at the TYPED layer, per field, where the schema is known.
// It is also simpler: no custom class, no composition.
//
// Build against an installed keyward (see README "Install and consume"):
//   g++ -std=c++20 $(pkg-config --cflags keyward) examples/headless_gatherer.cpp \
//       $(pkg-config --static --libs keyward)
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

#include "keyward/schema.hpp"
#include "keyward/vault.hpp"

namespace {

struct ApiCredential {
  std::string endpoint;
  std::string token;
  bool operator==(const ApiCredential&) const = default;

  static keyward::Schema<ApiCredential> schema() {
    return {
        {"endpoint", &ApiCredential::endpoint},
        {"token", &ApiCredential::token, keyward::Sensitive},
    };
  }
};

const char* env_or_null(const std::string& name) { return std::getenv(name.c_str()); }

// KEYWARD_<APP>_<SERVICE>_<FIELD>, upper-cased. Present-and-complete wins;
// a half-filled environment is a configuration error, not a partial credential.
std::optional<ApiCredential> from_environment(const std::string& app, const std::string& service) {
  std::string prefix = "KEYWARD_" + app + "_" + service + "_";
  for (char& c : prefix) c = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;

  const char* endpoint = env_or_null(prefix + "ENDPOINT");
  const char* token = env_or_null(prefix + "TOKEN");
  if (endpoint != nullptr && token != nullptr) return ApiCredential{endpoint, token};
  if (endpoint != nullptr || token != nullptr) {
    std::fprintf(stderr, "%s* is only partly set — refusing a half-configured credential\n",
                 prefix.c_str());
  }
  return std::nullopt;
}

}  // namespace

int main() {
  const std::string app = "gatherer";
  const std::string service = "warehouse";

  // Environment first: in a container this is the whole story, and nothing is
  // written to disk. On a developer's desktop the keychain still serves.
  std::optional<ApiCredential> cred = from_environment(app, service);

  if (!cred) {
    // load(), never ensure(). ensure() prompts, and there is nobody to ask —
    // absence here is a configuration error the caller reports.
    keyward::Vault vault{app};
    cred = vault.load<ApiCredential>(service);
  }

  if (!cred) {
    std::fprintf(stderr,
                 "no credentials for '%s'. Set KEYWARD_GATHERER_WAREHOUSE_ENDPOINT and "
                 "..._TOKEN, or store them once with an interactive run.\n",
                 service.c_str());
    return 2;
  }

  std::printf("gathering from %s with a %zu-character token\n", cred->endpoint.c_str(),
              cred->token.size());
  return 0;
}
