#pragma once
#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "keyward/record.hpp"  // Field, Fields

namespace keyward {

// Whether a field is a secret (masked in the TUI, wiped in memory). Carried on
// the schema for later layers; the Fields mapping below ignores it.
enum class Sensitivity { Plain, Sensitive };
inline constexpr Sensitivity Sensitive = Sensitivity::Sensitive;  // spelled keyward::Sensitive

// One entry in a record type's schema: the field's stored name and a
// pointer-to-member naming which std::string of the record it maps to.
// (Credential fields are std::string — email, url, token, api_key, ...)
template <class T>
struct FieldSpec {
  std::string name;
  std::string T::*member;
  Sensitivity sensitivity = Sensitivity::Plain;
};

// A record type declares `static Schema<T> schema()` listing its fields once.
template <class T>
using Schema = std::vector<FieldSpec<T>>;

// ---- the mapping (implement these — task 5) --------------------------------

// Read every schema member off `record`, in schema order, into a Fields list.
template <class T>
Fields to_fields(const T& record) {
  Fields out;
  for (const auto& spec : T::schema()) {
    out.push_back({spec.name, record.*(spec.member)});
  }
  return out;
}

// Rebuild a T: for each schema entry, find its named field in `fields` and
// assign it to the matching member. std::nullopt if a schema field is missing
// (unknown extra fields in `fields` are ignored). See docs/tasks/05-schema-mapping.md.
template <class T>
std::optional<T> from_fields(const Fields& fields) {
  T result{};

  for (const auto& spec : T::schema()) {
    auto it = std::find_if(fields.begin(), fields.end(),
                           [&](const Field& f) { return f.name == spec.name; });
    if (it == fields.end()) return std::nullopt;
    result.*(spec.member) = it->value;
  }
  return result;
}

}  // namespace keyward
