#include "keyward/keychain_secret_store.hpp"

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <utility>

namespace keyward {
namespace {

CFStringRef cfstr(const std::string& s) {
  return CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(s.data()),
                                 static_cast<CFIndex>(s.size()), kCFStringEncodingUTF8, false);
}

}  // namespace

KeychainSecretStore::KeychainSecretStore(std::string service) : service_(std::move(service)) {}

// Query dict matching one generic-password item (service, account). Caller CFReleases.
static CFMutableDictionaryRef baseQuery(const std::string& service, const std::string& account) {
  CFMutableDictionaryRef q = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks,
                                                       &kCFTypeDictionaryValueCallBacks);
  CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
  CFStringRef svc = cfstr(service);
  CFDictionarySetValue(q, kSecAttrService, svc);
  CFRelease(svc);
  CFStringRef acc = cfstr(account);
  CFDictionarySetValue(q, kSecAttrAccount, acc);
  CFRelease(acc);
  return q;
}

std::optional<std::string> KeychainSecretStore::get(const std::string& name) {
  CFMutableDictionaryRef q = baseQuery(service_, name);
  CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef result = nullptr;
  const OSStatus st = SecItemCopyMatching(q, &result);
  CFRelease(q);
  if (st != errSecSuccess || result == nullptr) return std::nullopt;
  CFDataRef data = reinterpret_cast<CFDataRef>(result);
  std::string out(reinterpret_cast<const char*>(CFDataGetBytePtr(data)),
                  static_cast<size_t>(CFDataGetLength(data)));
  CFRelease(result);
  return out;
}

void KeychainSecretStore::set(const std::string& name, const std::string& value) {
  remove(name);  // simplest upsert: delete any existing item, then add
  CFMutableDictionaryRef q = baseQuery(service_, name);
  CFDataRef data = CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(value.data()),
                                static_cast<CFIndex>(value.size()));
  CFDictionarySetValue(q, kSecValueData, data);
  SecItemAdd(q, nullptr);
  CFRelease(data);
  CFRelease(q);
}

void KeychainSecretStore::remove(const std::string& name) {
  CFMutableDictionaryRef q = baseQuery(service_, name);
  SecItemDelete(q);  // errSecItemNotFound is fine
  CFRelease(q);
}

}  // namespace keyward

#endif  // __APPLE__
