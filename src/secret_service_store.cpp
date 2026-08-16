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
// We use two: the namespaced app, and the caller's name.
constexpr const char* kAppAttr = "application";
constexpr const char* kNameAttr = "name";

// Namespaced exactly like the other two backends so two apps can't collide.
std::string appAttr(const std::string& app) { return "keyward:" + app; }

// libsecret validates attributes against a schema, and with SECRET_SCHEMA_NONE
// it matches the schema *name* too — so an item another program happened to
// write with a similar attribute set never comes back to us.
//
// Built imperatively rather than brace-initialised: SecretSchema carries trailing
// reserved members, and naming only the fields we care about would trip
// -Wmissing-field-initializers under -Wextra. `SecretSchema s{}` zeroes the lot.
const SecretSchema* keywardSchema() {
  static const SecretSchema schema = [] {
    SecretSchema s{};
    s.name = "com.keyward.Secret";
    s.flags = SECRET_SCHEMA_NONE;
    s.attributes[0] = {kAppAttr, SECRET_SCHEMA_ATTRIBUTE_STRING};
    s.attributes[1] = {kNameAttr, SECRET_SCHEMA_ATTRIBUTE_STRING};
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
AttrsPtr attributesFor(const std::string& app, const std::string* name = nullptr) {
  AttrsPtr attrs(g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free));
  const std::string a = appAttr(app);
  g_hash_table_insert(attrs.get(), g_strdup(kAppAttr), g_strdup(a.c_str()));
  if (name != nullptr)
    g_hash_table_insert(attrs.get(), g_strdup(kNameAttr), g_strdup(name->c_str()));
  return attrs;
}

// GLib's message describes the D-Bus/daemon failure, never our value. The secret
// name is safe to surface; the secret itself never appears in any message.
[[noreturn]] void fail(const std::string& what, const ErrorPtr& err) {
  std::string msg = "keyward: Secret Service " + what + " failed";
  if (err) msg += ": " + std::string(err->message);
  throw std::runtime_error(msg);
}

}  // namespace

SecretServiceStore::SecretServiceStore(std::string app) : app_(std::move(app)) {}

std::optional<std::string> SecretServiceStore::get(const std::string& name) {
  AttrsPtr attrs = attributesFor(app_, &name);
  GError* rawErr = nullptr;
  ValuePtr value(
      secret_service_lookup_sync(nullptr, keywardSchema(), attrs.get(), nullptr, &rawErr));
  ErrorPtr err(rawErr);
  if (!value) {
    // NULL with no error is a genuine miss. NULL *with* an error is a failure,
    // and laundering it into "not found" would be the silent downgrade the
    // fail-closed invariant forbids.
    if (err) fail("lookup for '" + name + "'", err);
    return std::nullopt;
  }
  gsize len = 0;
  const gchar* bytes = secret_value_get(value.get(), &len);
  if (bytes == nullptr) return std::string();
  // Counted copy: `bytes` is not a C string and may contain NULs.
  return std::string(bytes, static_cast<size_t>(len));
}

void SecretServiceStore::set(const std::string& name, const std::string& value) {
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
    // attribute, so there's no prefix to strip here (unlike Windows).
    const auto* n = static_cast<const gchar*>(g_hash_table_lookup(got.get(), kNameAttr));
    if (n != nullptr) names.emplace_back(n);
  }
  return names;
}

}  // namespace keyward

#endif  // __linux__ && KEYWARD_HAVE_LIBSECRET
