#pragma once
#include <string>
#include <string_view>

namespace keyward {

inline void secure_wipe(void* p, std::size_t n) noexcept {
  volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
  while (n--) *v++ = 0;
}

class Secret {
 public:
  explicit Secret(std::string bytes) : bytes_(std::move(bytes)) {}
  ~Secret() { secure_wipe(bytes_.data(), bytes_.size()); }
  Secret(Secret&& secret) noexcept : bytes_(std::move(secret.bytes_)) {}
  Secret& operator=(Secret&& secret) noexcept {
    if (this != &secret) {
      secure_wipe(bytes_.data(), bytes_.size());
      bytes_ = std::move(secret.bytes_);
    }
    return *this;
  }

  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  std::string_view view() const noexcept { return bytes_; }
  std::size_t size() const noexcept { return bytes_.size(); }
  bool empty() const noexcept { return bytes_.empty(); }
  std::string redacted() const { return std::string(size(), '*'); }

  bool equals(std::string_view candidate) const noexcept {
    if (bytes_.size() != candidate.size()) return false;
    volatile unsigned char m{};
    for (std::size_t i{}; i < bytes_.size(); ++i) {
      m |= bytes_[i] ^ candidate[i];
    }
    return (m == 0);
  }

 private:
  std::string bytes_;
};
}  // namespace keyward
