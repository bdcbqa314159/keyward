#include "keyward/keychain_secret_store.hpp"

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "keyward/secure_memory.hpp"  // secure_zero (R3-2: scrub CF buffer)

namespace keyward {
namespace {

// Build a human-readable error from an OSStatus. Never includes any secret
// value — only the numeric status and the OS's own message text.
std::string statusError(const std::string& what, OSStatus st) {
  std::string out = "keyward: Keychain " + what + " failed (status " + std::to_string(st);
  if (CFStringRef msg = SecCopyErrorMessageString(st, nullptr)) {
    char buf[256];
    if (CFStringGetCString(msg, buf, sizeof(buf), kCFStringEncodingUTF8)) {
      out += std::string(", ") + buf;
    }
    CFRelease(msg);
  }
  out += ")";
  return out;
}

// UTF-8 -> CFString. CFStringCreateWithBytes returns NULL on invalid UTF-8;
// throw before it reaches CoreFoundation (which would CFRetain(NULL) and crash).
CFStringRef cfstr(const std::string& s) {
  CFStringRef r =
      CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(s.data()),
                              static_cast<CFIndex>(s.size()), kCFStringEncodingUTF8, false);
  if (r == nullptr) throw std::runtime_error("keyward: invalid UTF-8 in a Keychain key");
  return r;
}

// Query dict matching one generic-password item (service, account). Caller
// CFReleases. Validates both strings up front so a bad key can't leak `q`.
CFMutableDictionaryRef baseQuery(const std::string& service, const std::string& account) {
  CFStringRef svc = cfstr(service);
  CFStringRef acc = nullptr;
  try {
    acc = cfstr(account);
  } catch (...) {
    CFRelease(svc);
    throw;
  }
  CFMutableDictionaryRef q = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                                       &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(q, kSecAttrService, svc);
  CFDictionarySetValue(q, kSecAttrAccount, acc);
  CFRelease(svc);
  CFRelease(acc);
  return q;
}

}  // namespace

KeychainSecretStore::KeychainSecretStore(std::string service) : service_(std::move(service)) {}

std::optional<std::string> KeychainSecretStore::get(const std::string& name) {
  CFMutableDictionaryRef q = baseQuery(service_, name);
  CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef result = nullptr;
  const OSStatus st = SecItemCopyMatching(q, &result);
  CFRelease(q);
  // Only a genuine miss is "no such secret". Every other status (locked keychain,
  // interaction not allowed, auth failed, ...) is an ERROR — throwing it prevents
  // a silent read-through to a weaker fallback tier.
  if (st == errSecItemNotFound) return std::nullopt;
  if (st != errSecSuccess) throw std::runtime_error(statusError("read", st));
  if (result == nullptr) return std::nullopt;
  CFDataRef data = reinterpret_cast<CFDataRef>(result);
  const CFIndex len = CFDataGetLength(data);
  std::string out(reinterpret_cast<const char*>(CFDataGetBytePtr(data)), static_cast<size_t>(len));
  // R3-2: scrub the plaintext from the CF buffer before releasing it. CFRelease
  // frees without zeroing, so the secret would linger in freed heap — the same
  // leak the Windows (SecureZeroMemory) and libsecret (secret_value_unref)
  // backends already close. SecItemCopyMatching returned a +1 CFData we own and
  // are about to free, so overwriting it in place is safe; secure_zero is not
  // optimized away.
  if (len > 0) secure_zero(const_cast<UInt8*>(CFDataGetBytePtr(data)), static_cast<size_t>(len));
  CFRelease(result);
  return out;
}

void KeychainSecretStore::set(const std::string& name, std::string_view value) {
  CFMutableDictionaryRef q = baseQuery(service_, name);  // may throw on bad UTF-8
  CFDataRef data = CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(value.data()),
                                static_cast<CFIndex>(value.size()));
  // Upsert without delete-first: update an existing item, else add. A failure can
  // never empty the slot (the old delete-then-add could lose the secret if the
  // add failed), and the result is always checked.
  CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
      nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(attrs, kSecValueData, data);
  // R3-9: reassert the accessibility class on update too, not just on add. An
  // item first created by another tool (e.g. Python keyring uses the weaker,
  // syncable kSecAttrAccessibleWhenUnlocked) would otherwise keep its foreign
  // class through our writes — so the "WhenUnlockedThisDeviceOnly, device-bound"
  // invariant would hold only for items keyward created.
  CFDictionarySetValue(attrs, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
  OSStatus st = SecItemUpdate(q, attrs);
  CFRelease(attrs);
  if (st == errSecItemNotFound) {
    CFDictionarySetValue(q, kSecValueData, data);
    // Bind an explicit data-protection class: readable only while unlocked, and
    // never migrated off this device.
    CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    st = SecItemAdd(q, nullptr);
  }
  CFRelease(data);
  CFRelease(q);
  if (st != errSecSuccess) throw std::runtime_error(statusError("write", st));
}

void KeychainSecretStore::remove(const std::string& name) {
  CFMutableDictionaryRef q = baseQuery(service_, name);
  const OSStatus st = SecItemDelete(q);
  CFRelease(q);
  if (st == errSecItemNotFound) return;  // already absent
  if (st != errSecSuccess) throw std::runtime_error(statusError("delete", st));
  // Verify the item is really gone — a locked keychain could no-op a delete and
  // leave a "revoked" credential in place. Attributes-only query (no secret load).
  CFMutableDictionaryRef check = baseQuery(service_, name);
  CFDictionarySetValue(check, kSecMatchLimit, kSecMatchLimitOne);
  const OSStatus vst = SecItemCopyMatching(check, nullptr);
  CFRelease(check);
  if (vst != errSecItemNotFound)
    throw std::runtime_error("keyward: Keychain item still present after delete");
}

std::vector<std::string> KeychainSecretStore::list() {
  CFMutableDictionaryRef q = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                                       &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
  CFStringRef svc = cfstr(service_);
  CFDictionarySetValue(q, kSecAttrService, svc);
  CFRelease(svc);
  CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);  // names only, no secret data
  CFTypeRef result = nullptr;
  const OSStatus st = SecItemCopyMatching(q, &result);
  CFRelease(q);
  if (st == errSecItemNotFound) return {};
  if (st != errSecSuccess) throw std::runtime_error(statusError("list", st));

  std::vector<std::string> names;
  CFArrayRef items = reinterpret_cast<CFArrayRef>(result);
  const CFIndex n = CFArrayGetCount(items);
  for (CFIndex i = 0; i < n; ++i) {
    CFDictionaryRef item = reinterpret_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(items, i));
    CFStringRef acc = reinterpret_cast<CFStringRef>(CFDictionaryGetValue(item, kSecAttrAccount));
    if (acc == nullptr) continue;
    const CFIndex cap =
        CFStringGetMaximumSizeForEncoding(CFStringGetLength(acc), kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<size_t>(cap), '\0');
    if (CFStringGetCString(acc, buf.data(), cap, kCFStringEncodingUTF8)) {
      buf.resize(std::strlen(buf.c_str()));
      names.push_back(std::move(buf));
    }
  }
  CFRelease(result);
  return names;
}

}  // namespace keyward

#endif  // __APPLE__
