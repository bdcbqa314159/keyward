# Task 5 — Typed schema mapping (`to_fields` / `from_fields`)

**Goal.** Bridge a *typed* record (`JiraCredential{email,url,token}`) and the
generic `Fields` list, both directions, driven by the record's `schema()`. This
is the "single source of truth" layer: declare the fields once, get both the
save path and the load path from it. On top of the codec (`Fields ⇄ bytes`),
this closes the gap to `struct ⇄ bytes`.

## The contract

Implement these in `include/keyward/schema.hpp`. They're **templates**, so the
bodies live in the header (not a `.cpp`).

```cpp
template <class T> Fields to_fields(const T& record);
template <class T> std::optional<T> from_fields(const Fields& fields);
```

A record type declares its schema once:

```cpp
struct DemoCred {
  std::string email, url, token;
  static keyward::Schema<DemoCred> schema() {
    return {{"email", &DemoCred::email},
            {"url",   &DemoCred::url},
            {"token", &DemoCred::token, keyward::Sensitive}};
  }
};
```

- `to_fields(record)` → a `Fields` list, one per schema entry, **in schema order**.
- `from_fields<T>(fields)` → a rebuilt `T`, or **`std::nullopt`** if a schema
  field is missing from `fields`. Match by **name** (order-independent), and
  **ignore** any extra fields the schema doesn't know about.

---

## The new concept — pointer-to-member

The whole trick is `std::string T::*` — a **pointer to a member**. Read it as:
*"the `email` slot of some `DemoCred`"* — it names a field **without** naming a
particular object. `&DemoCred::email` is a value of that type.

You can't read it on its own — you have to say *which object's* slot, using the
`.*` operator:

```cpp
std::string DemoCred::*m = &DemoCred::email;  // "the email slot"
DemoCred c{...};
std::string got = c.*m;    // open that slot on c   -> c.email
c.*m = "new@addr";         // assign through it      -> c.email = "new@addr"
```

Mental model: the member pointer is a **key**; `.*` opens that slot on a specific
object. In your loops `m` is `spec.member`, so — mind the precedence, wrap it:

```cpp
record.*(spec.member)      // read
result.*(spec.member) = v; // write
```

That indirection is exactly what lets one generic loop serve every record type:
the schema hands you the key (`spec.member`) and the name (`spec.name`), and you
never mention `email`/`url`/`token` by hand.

---

## Translating the concept into code

### `to_fields` — read each member out

```
Fields out;
for each spec in T::schema():
    out.push_back({ spec.name, record.*(spec.member) });   // name + the member's value
return out;
```

### `from_fields` — put each member back

```
T result{};                          // default-constructed, empty strings
for each spec in T::schema():
    find the Field in `fields` whose .name == spec.name
    if not found            -> return std::nullopt
    result.*(spec.member) = found.value;
return result;
```

Finding by name is a small linear scan — `std::find_if` with a lambda:

```cpp
auto it = std::find_if(fields.begin(), fields.end(),
                       [&](const Field& f) { return f.name == spec.name; });
if (it == fields.end()) return std::nullopt;
// it->value is the string to assign
```

A linear scan per field is fine here — records have a handful of fields, not
thousands. (Don't reach for a map.)

## Rules

- **Don't edit the tests** — make the mapping satisfy them.
- `from_fields` matches by **name**, not position — the input may be in any order
  and may carry extra fields you ignore. Missing a schema field → `nullopt`.
- `<algorithm>` for `std::find_if`.

## Verify

```sh
cmake --build --preset debug && ctest --preset debug -R Schema --output-on-failure
cmake --preset asan && cmake --build --preset asan && ctest --preset asan -R Schema
```

**Done** = all 5 `Schema` tests green on **debug** and **asan**, clang-format clean.
