#pragma once
#include <cstddef>

namespace keyward {

// Thin wrapper over libsodium's secure-memory primitives. libsodium is a PRIVATE
// implementation detail — it's included only in secure_memory.cpp, never here, so
// consumers of keyward don't inherit <sodium.h>.

// Guard-paged, mlock'd allocation the OS won't swap to disk, sized exactly `n`.
// Returns nullptr on failure or n == 0. Free with secure_free (which also zeroes).
void* secure_alloc(std::size_t n);
void secure_free(void* p);

// Overwrite `n` bytes at `p` with zero, in a way the compiler can't elide.
void secure_zero(void* p, std::size_t n);

// Constant-time equality of two n-byte buffers (no early-out on first difference).
bool secure_equal(const void* a, const void* b, std::size_t n);

// Fill `p` with `n` cryptographically-secure random bytes (OS CSPRNG).
void secure_random(void* p, std::size_t n);

}  // namespace keyward
