#include "keyward/random.hpp"

#include <random>

namespace keyward {

std::string random_bytes(std::size_t n) {
  // ponytail: std::random_device — non-deterministic OS entropy on the macOS /
  // Linux / Windows CI targets. The standard doesn't *guarantee* a CSPRNG, so
  // the harden pass swaps this for arc4random_buf / getrandom / BCryptGenRandom.
  // Adequate for salt + nonce in the learning build.
  std::random_device rd;
  std::string out(n, '\0');
  for (auto& b : out) {
    b = static_cast<char>(rd());
  }
  return out;
}

}  // namespace keyward
