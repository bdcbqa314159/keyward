#pragma once
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

#include "keyward/secure_memory.hpp"

namespace keyward {

// A secret byte buffer held in libsodium secure memory: guard-paged, mlock'd
// (never swapped to disk), and zeroed on destruction. Move-only; redacts itself
// in any textual form. libsodium stays private (behind secure_memory.hpp).
class Secret {
 public:
  explicit Secret(std::string_view bytes) : size_(bytes.size()) {
    data_ = static_cast<unsigned char*>(secure_alloc(size_));
    if (size_) std::memcpy(data_, bytes.data(), size_);
  }
  ~Secret() { secure_free(data_); }  // secure_free zeroes the region before releasing

  Secret(Secret&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }
  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) {
      secure_free(data_);
      data_ = other.data_;
      size_ = other.size_;
      other.data_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;

  std::string_view view() const noexcept { return {reinterpret_cast<const char*>(data_), size_}; }
  std::size_t size() const noexcept { return size_; }
  bool empty() const noexcept { return size_ == 0; }
  std::string redacted() const { return std::string(size_, '*'); }

  // Constant-time comparison against a candidate (libsodium sodium_memcmp).
  bool equals(std::string_view candidate) const noexcept {
    if (candidate.size() != size_) return false;
    return secure_equal(data_, candidate.data(), size_);
  }

 private:
  unsigned char* data_ = nullptr;
  std::size_t size_ = 0;
};

}  // namespace keyward
