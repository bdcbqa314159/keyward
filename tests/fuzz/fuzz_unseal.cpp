// libFuzzer harness for the encrypted-blob parser. unseal() parses fully
// attacker-controlled bytes (a stored/transmitted blob) before the AEAD check,
// so its length/bounds handling must survive arbitrary garbage. Passphrase is
// fixed — we're fuzzing the parse + auth path, not the KDF.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "keyward/secret_box.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  keyward::unseal(std::string_view(reinterpret_cast<const char*>(data), size), "correct horse");
  return 0;
}
