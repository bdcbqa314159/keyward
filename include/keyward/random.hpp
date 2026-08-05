#pragma once
#include <cstddef>
#include <string>

namespace keyward {

// Returns a fresh string of `n` cryptographically-random bytes. Use it for
// salts and nonces. (Plumbing — provided; you don't need to touch this.)
std::string random_bytes(std::size_t n);

}  // namespace keyward
