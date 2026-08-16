#include "keyward/secret_service_store.hpp"

#if defined(__linux__) && defined(KEYWARD_HAVE_LIBSECRET)

#include <libsecret/secret.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keyward {
namespace {

// Secret Service identifies an item by its *attribute set*, not by one key
// string — there is no "target name" like Windows, no (service, account) pair
// like the Keychain. A lookup is a query: "the item whose attributes are these".
//
// The vocabulary is NOT ours to invent. DESIGN.md's compatibility north star is
// that a secret written by Python `keyring` is readable by keyward and vice
// versa, and `keyring` is the de-facto convention on this bus: it writes
// {service, username, application} and looks items up on {service, username}
// alone (`application` is never matched — see SchemeSelectable._query). So we
// speak the same two attributes, mapping keyward's (app, name) onto them.
constexpr const char* kServiceAttr = "service";    // keyward's `app` namespace
constexpr const char* kUsernameAttr = "username";  // keyward's secret `name`

// The schema. Two deliberate choices:
//
//  - name "org.freedesktop.Secret.Generic", not a keyward-private one: that is
//    the generic schema items on this bus carry, and a private name would
//    partition us away from every other client.
//  - SECRET_SCHEMA_DONT_MATCH_NAME, so libsecret does NOT fold the schema name
//    into the match. Items written by other clients may carry a different
//    `xdg:schema` (or none at all); matching on it would silently hide exactly
//    the items interop exists to find. We match on the attributes only.
//
// Built imperatively rather than brace-initialised: SecretSchema carries trailing
// reserved members, and naming only the fields we care about would trip
// -Wmissing-field-initializers under -Wextra. `SecretSchema s{}` zeroes the lot.
const SecretSchema* keywardSchema() {
  static const SecretSchema schema = [] {
    SecretSchema s{};
    s.name = "org.freedesktop.Secret.Generic";
    s.flags = SECRET_SCHEMA_DONT_MATCH_NAME;
    s.attributes[0] = {kServiceAttr, SECRET_SCHEMA_ATTRIBUTE_STRING};
    s.attributes[1] = {kUsernameAttr, SECRET_SCHEMA_ATTRIBUTE_STRING};
    // attributes[2] stays {nullptr, ...} — the terminator libsecret scans for.
    return s;
  }();
  return &schema;
}

// GLib/libsecret hand back raw owning pointers across calls that can throw.
// Stateless deleters so these cost nothing over the bare pointer.
struct GErrorDeleter {
  void operator()(GError* e) const { g_error_free(e); }
};
struct HashTableDeleter {
  void operator()(GHashTable* t) const { g_hash_table_unref(t); }
};
struct SecretValueDeleter {
  // Not just a free: libsecret allocates secret memory from its own pool and
  // wipes it here. This is the analogue of SecureZeroMemory in the Windows
  // backend — the reason we must not reach for plain g_free.
  void operator()(SecretValue* v) const { secret_value_unref(v); }
};
struct ItemListDeleter {
  void operator()(GList* l) const { g_list_free_full(l, g_object_unref); }
};
using ErrorPtr = std::unique_ptr<GError, GErrorDeleter>;
using AttrsPtr = std::unique_ptr<GHashTable, HashTableDeleter>;
using ValuePtr = std::unique_ptr<SecretValue, SecretValueDeleter>;
using ItemListPtr = std::unique_ptr<GList, ItemListDeleter>;

// Attribute table for one item, or (name == nullptr) a partial table matching
// every item in this app's namespace — which is what list() searches on.
//
// We store exactly these two attributes and no more. `keyring` additionally
// stamps application="Python keyring library", but an attribute we store is
// also an attribute that must match for a *write* to replace in place — so
// adding our own third attribute would make keyward unable to overwrite an item
// keyring wrote, and vice versa. Storing the minimal set keeps our attributes a
// subset of theirs, which is what makes reads work in both directions.
AttrsPtr attributesFor(const std::string& app, const std::string* name = nullptr) {
  AttrsPtr attrs(g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free));
  g_hash_table_insert(attrs.get(), g_strdup(kServiceAttr), g_strdup(app.c_str()));
  if (name != nullptr)
    g_hash_table_insert(attrs.get(), g_strdup(kUsernameAttr), g_strdup(name->c_str()));
  return attrs;
}

// GLib's message describes the D-Bus/daemon failure, never our value. The secret
// name is safe to surface; the secret itself never appears in any message.
[[noreturn]] void fail(const std::string& what, const ErrorPtr& err) {
  std::string msg = "keyward: Secret Service " + what + " failed";
  if (err) msg += ": " + std::string(err->message);
  throw std::runtime_error(msg);
}

// Copies a SecretValue's bytes out. Counted: not a C string, may contain NULs.
std::optional<std::string> valueBytes(SecretValue* v) {
  if (v == nullptr) return std::nullopt;
  gsize len = 0;
  const gchar* bytes = secret_value_get(v, &len);
  if (bytes == nullptr) return std::string();
  return std::string(bytes, static_cast<size_t>(len));
}

}  // namespace

SecretServiceStore::SecretServiceStore(std::string app) : app_(std::move(app)) {}

std::optional<std::string> SecretServiceStore::get(const std::string& name) {
  // Search rather than lookup, because MORE THAN ONE item can match. Secret
  // Service replaces an item on an EXACT attribute-set match, and Python
  // keyring stores a third attribute (application) that we deliberately don't —
  // so a keyring write over our item ADDS a second item instead of replacing
  // ours, leaving a stale twin. secret_service_lookup_sync would return an
  // arbitrary one of them, which made reads silently order-dependent.
  //
  // LOAD_SECRETS here (unlike list(), which needs attributes only) because the
  // caller is asking for exactly this secret, and we must compare values to
  // tell a harmless duplicate from a genuine conflict.
  AttrsPtr attrs = attributesFor(app_, &name);
  GError* rawErr = nullptr;
  ItemListPtr items(secret_service_search_sync(
      nullptr, keywardSchema(), attrs.get(),
      static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL | SECRET_SEARCH_LOAD_SECRETS), nullptr,
      &rawErr));
  ErrorPtr err(rawErr);
  // An error is a failure; laundering it into "not found" would be the silent
  // downgrade the fail-closed invariant forbids. No error and no items is a miss.
  if (err) fail("lookup for '" + name + "'", err);
  if (!items) return std::nullopt;

  // Newest wins. `modified` has ONE-SECOND granularity, so two writes inside the
  // same second tie — and if a tie holds two different values we genuinely
  // cannot tell which is current. Guessing there would hand back a stale secret,
  // so we refuse (fail closed). The next set() collapses the duplicates.
  std::optional<std::string> best;
  guint64 bestAt = 0;
  bool ambiguous = false;
  for (GList* node = items.get(); node != nullptr; node = node->next) {
    auto* item = static_cast<SecretItem*>(node->data);
    ValuePtr value(secret_item_get_secret(item));
    std::optional<std::string> bytes = valueBytes(value.get());
    if (!bytes) continue;
    const guint64 at = secret_item_get_modified(item);
    if (!best || at > bestAt) {
      best = std::move(bytes);
      bestAt = at;
      ambiguous = false;
    } else if (at == bestAt && *bytes != *best) {
      ambiguous = true;  // same timestamp, different value — undecidable
    }
  }
  if (ambiguous) {
    throw std::runtime_error("keyward: '" + name +
                             "' matches multiple Secret Service items last modified in the same "
                             "second with differing values; refusing to guess which is current "
                             "(overwrite it to resolve)");
  }
  return best;
}

void SecretServiceStore::set(const std::string& name, const std::string& value) {
  // Clear first, then store — the same "simplest upsert" the macOS Keychain
  // backend uses, and here it also COLLAPSES duplicates. Storing alone only
  // replaces an item whose attribute set matches ours exactly, so a twin left
  // behind by another client (see get()) would survive and keep shadowing us.
  // clear matches on our two attributes, so it takes those out too.
  remove(name);

  AttrsPtr attrs = attributesFor(app_, &name);
  // SecretValue is length-counted; the simpler secret_password_store_sync takes
  // a `const gchar*` password and would stop at the first NUL. Vault::save
  // stores encode_fields() output — length-prefixed binary that routinely
  // contains NULs — so the counted path is the only correct one here.
  ValuePtr sv(secret_value_new(value.data(), static_cast<gssize>(value.size()),
                               "application/octet-stream"));
  // Shown when the user browses Seahorse / KDE Wallet Manager — never a secret.
  const std::string label = "keyward: " + app_ + "/" + name;
  GError* rawErr = nullptr;
  const gboolean ok =
      secret_service_store_sync(nullptr, keywardSchema(), attrs.get(), SECRET_COLLECTION_DEFAULT,
                                label.c_str(), sv.get(), nullptr, &rawErr);
  ErrorPtr err(rawErr);
  // Upsert: an existing item with these attributes is replaced in place.
  if (!ok) fail("store for '" + name + "'", err);
}

void SecretServiceStore::remove(const std::string& name) {
  AttrsPtr attrs = attributesFor(app_, &name);
  GError* rawErr = nullptr;
  // Returns FALSE both when nothing matched and when the call failed — the
  // GError is what distinguishes them. A missing name is a no-op, not an error.
  secret_service_clear_sync(nullptr, keywardSchema(), attrs.get(), nullptr, &rawErr);
  ErrorPtr err(rawErr);
  if (err) fail("clear for '" + name + "'", err);
}

std::vector<std::string> SecretServiceStore::list() {
  // Partial attribute match (app only), so every name in this namespace comes
  // back. SECRET_SEARCH_ALL returns every match rather than just the first; we
  // deliberately do NOT pass SECRET_SEARCH_LOAD_SECRETS — listing needs the
  // attributes only, and pulling every secret into memory to print names would
  // be exposure for nothing.
  AttrsPtr attrs = attributesFor(app_);
  GError* rawErr = nullptr;
  ItemListPtr items(secret_service_search_sync(nullptr, keywardSchema(), attrs.get(),
                                               SECRET_SEARCH_ALL, nullptr, &rawErr));
  ErrorPtr err(rawErr);
  if (err) fail("search", err);

  std::vector<std::string> names;
  for (GList* node = items.get(); node != nullptr; node = node->next) {
    AttrsPtr got(secret_item_get_attributes(static_cast<SecretItem*>(node->data)));
    if (!got) continue;
    // Names come back unqualified — the namespace lives in the *other*
    // attribute, so there's no prefix to strip here (unlike Windows). Items
    // another client wrote under this service are listed too; that is the point.
    const auto* n = static_cast<const gchar*>(g_hash_table_lookup(got.get(), kUsernameAttr));
    if (n != nullptr) names.emplace_back(n);
  }
  return names;
}

}  // namespace keyward

#endif  // __linux__ && KEYWARD_HAVE_LIBSECRET
