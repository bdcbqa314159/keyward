// libFuzzer harness for the record codec's parser. decode_fields() takes
// attacker-controlled bytes (whatever was in a stored item), so it must never
// crash or read out of bounds on garbage. Coverage-guided fuzzing hunts for that.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "keyward/record.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  keyward::decode_fields(std::string_view(reinterpret_cast<const char*>(data), size));
  return 0;
}
