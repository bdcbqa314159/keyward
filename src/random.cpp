#include "keyward/random.hpp"

#include "keyward/secure_memory.hpp"

namespace keyward {

std::string random_bytes(std::size_t n) {
  std::string out(n, '\0');
  secure_random(out.data(), n);  // libsodium CSPRNG (randombytes_buf)
  return out;
}

}  // namespace keyward
