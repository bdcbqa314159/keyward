#include "keyward/base64.hpp"

#include <cstddef>
#include <cstdint>

namespace keyward {
namespace {

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

}  // namespace

std::string base64_encode(std::string_view in) {
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  auto byte = [&](std::size_t i) {
    return static_cast<uint32_t>(static_cast<unsigned char>(in[i]));
  };
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    uint32_t n = (byte(i) << 16) | (byte(i + 1) << 8) | byte(i + 2);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back(kB64[n & 63]);
  }
  if (const std::size_t rem = in.size() - i; rem == 1) {
    uint32_t n = byte(i) << 16;
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.append("==");
  } else if (rem == 2) {
    uint32_t n = (byte(i) << 16) | (byte(i + 1) << 8);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

std::optional<std::string> base64_decode(std::string_view in) {
  if (in.size() % 4 != 0) return std::nullopt;
  std::string out;
  out.reserve(in.size() / 4 * 3);
  for (std::size_t i = 0; i < in.size(); i += 4) {
    const int a = b64_val(in[i]);
    const int b = b64_val(in[i + 1]);
    if (a < 0 || b < 0) return std::nullopt;
    const char c3 = in[i + 2];
    const char c4 = in[i + 3];
    uint32_t n = (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12);
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    if (c3 == '=') {
      if (c4 != '=' || i + 4 != in.size()) return std::nullopt;  // padding only at the very end
    } else {
      const int c = b64_val(c3);
      if (c < 0) return std::nullopt;
      n |= static_cast<uint32_t>(c) << 6;
      out.push_back(static_cast<char>((n >> 8) & 0xFF));
      if (c4 == '=') {
        if (i + 4 != in.size()) return std::nullopt;
      } else {
        const int d = b64_val(c4);
        if (d < 0) return std::nullopt;
        n |= static_cast<uint32_t>(d);
        out.push_back(static_cast<char>(n & 0xFF));
      }
    }
  }
  return out;
}

}  // namespace keyward
