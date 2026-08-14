#include "keyward/secure_memory.hpp"

#include <sodium.h>

namespace keyward {
namespace {

// libsodium needs one-time initialisation before first use. A function-local
// static makes it happen exactly once, thread-safely, before the first call.
void ensure_init() {
  static const int rc = sodium_init();  // -1 only on catastrophic failure
  (void)rc;
}

}  // namespace

void* secure_alloc(std::size_t n) {
  ensure_init();
  return n == 0 ? nullptr : sodium_malloc(n);
}

void secure_free(void* p) {
  if (p) sodium_free(p);  // sodium_free zeroes the region before releasing it
}

void secure_zero(void* p, std::size_t n) {
  if (p && n) sodium_memzero(p, n);
}

bool secure_equal(const void* a, const void* b, std::size_t n) {
  return sodium_memcmp(a, b, n) == 0;
}

void secure_random(void* p, std::size_t n) {
  ensure_init();
  if (p && n) randombytes_buf(p, n);
}

}  // namespace keyward
