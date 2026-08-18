#pragma once
#include <cstddef>
#include <limits>
#include <new>
#include <string>

#include "keyward/secure_memory.hpp"

namespace keyward {

// An allocator that zeroes a block before releasing it.
//
// WHY THIS EXISTS, and why wiping at the end is not enough. `Secret` protects a
// buffer you hold. It cannot protect the buffers a growing `std::string` leaves
// behind: every reallocation copies the contents into a larger block and frees
// the old one **untouched**. Serializing a record with `out += value` therefore
// scatters prefixes of that record — secret values included — across freed heap,
// and a `secure_zero(s.data(), s.size())` afterwards reaches only the final
// block. The leak is invisible to any end-of-life wipe, because the leaked
// blocks are no longer reachable from the string.
//
// Putting the zeroing in the *allocator* fixes it structurally: every block the
// container ever releases goes through deallocate(), including the ones shed by
// growth, and including the last one at destruction. Nothing has to remember to
// wipe, and nothing can forget.
//
// This is NOT libsodium's guarded allocation (`secure_alloc`). That gives guard
// pages and no-swap but costs several pages per allocation, which is right for a
// long-lived key and wrong for a transient buffer that may be resized often.
// This trades those extra protections for the one property that matters here —
// no plaintext left in freed memory. Use `Secret` for keys; use this for
// in-flight bytes.
template <class T>
struct SecureAllocator {
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <class U>
  explicit SecureAllocator(const SecureAllocator<U>&) noexcept {}

  T* allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) throw std::bad_alloc();
    return static_cast<T*>(::operator new(n * sizeof(T)));
  }

  void deallocate(T* p, std::size_t n) noexcept {
    if (p != nullptr) secure_zero(p, n * sizeof(T));  // the whole point
    ::operator delete(p);
  }

  // Allocators comparing equal means memory from one can be freed by the other,
  // which is true here — they are stateless and both use ::operator new/delete.
  template <class U>
  bool operator==(const SecureAllocator<U>&) const noexcept {
    return true;
  }
  template <class U>
  bool operator!=(const SecureAllocator<U>&) const noexcept {
    return false;
  }
};

// A std::string that leaves nothing behind. Same interface as std::string, so it
// takes part in the usual conversions: it converts to std::string_view freely,
// which is how it reaches APIs that take one without copying.
//
// Caveat worth knowing: short strings live inside the object (SSO) and never
// touch the allocator, so their bytes are wiped only when something wipes the
// object. That is fine for the record blob, which is far past the SSO limit.
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

}  // namespace keyward
