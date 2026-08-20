// Touches the pieces most likely to break in a packaged build: a public header,
// secure memory (libsodium, linked privately), and the backend chain (libsecret
// on Linux). If the export set or the private-dependency handling is wrong, this
// fails to link rather than failing subtly at runtime.
#include <cstdio>
#include <string>

#include "keyward/schema.hpp"
#include "keyward/secret.hpp"
#include "keyward/vault.hpp"

struct Cred {
  std::string user, token;
  bool operator==(const Cred&) const = default;
  static keyward::Schema<Cred> schema() {
    return {{"user", &Cred::user}, {"token", &Cred::token, keyward::Sensitive}};
  }
};

int main() {
  keyward::Secret s("hello");
  if (s.redacted() != "*****") return 1;
  keyward::Vault vault{"keyward-consumer-test"};  // constructs the platform store
  std::printf("installed keyward is consumable\n");
  return 0;
}
