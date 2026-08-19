#include "keyward/polkit_authenticator.hpp"

#if defined(__linux__) && defined(KEYWARD_HAVE_POLKIT)

#include <polkit/polkit.h>
#include <unistd.h>

#include <memory>
#include <string>

namespace keyward {
namespace {

// Same stateless-deleter pattern as the Secret Service backend: GLib hands back
// owning raw pointers across calls that can throw or early-return.
struct GErrorDeleter {
  void operator()(GError* e) const { g_error_free(e); }
};
struct GObjectDeleter {
  void operator()(void* o) const { g_object_unref(o); }
};
struct GListDeleter {
  void operator()(GList* l) const { g_list_free_full(l, g_object_unref); }
};
using ErrorPtr = std::unique_ptr<GError, GErrorDeleter>;
using AuthorityPtr = std::unique_ptr<PolkitAuthority, GObjectDeleter>;
using SubjectPtr = std::unique_ptr<PolkitSubject, GObjectDeleter>;
using ResultPtr = std::unique_ptr<PolkitAuthorizationResult, GObjectDeleter>;
using ActionListPtr = std::unique_ptr<GList, GListDeleter>;

AuthorityPtr authority(ErrorPtr& err) {
  GError* raw = nullptr;
  AuthorityPtr a(polkit_authority_get_sync(nullptr, &raw));
  err.reset(raw);
  return a;
}

// polkit treats an unregistered action as "not authorized", which is
// indistinguishable from a real refusal at the result level. Asking the
// authority to enumerate its actions is what lets us tell "the policy file was
// never installed" from "the user said no" — and it needs no agent, so it works
// headlessly.
bool actionRegistered(PolkitAuthority* auth) {
  GError* raw = nullptr;
  ActionListPtr actions(polkit_authority_enumerate_actions_sync(auth, nullptr, &raw));
  ErrorPtr err(raw);
  if (err || !actions) return false;
  for (GList* n = actions.get(); n != nullptr; n = n->next) {
    const gchar* id =
        polkit_action_description_get_action_id(static_cast<PolkitActionDescription*>(n->data));
    if (id != nullptr && kPolkitActionId == std::string(id)) return true;
  }
  return false;
}

// The subject is this process. polkit wants a start time alongside the pid so a
// recycled pid cannot be mistaken for us; 0 asks it to read the real one from
// /proc rather than trusting a value we pass in.
SubjectPtr selfSubject() {
  return SubjectPtr(polkit_unix_process_new_for_owner(getpid(), 0, getuid()));
}

}  // namespace

bool polkit_available() {
  ErrorPtr err;
  AuthorityPtr auth = authority(err);
  if (!auth) return false;              // no system bus / no polkitd
  return actionRegistered(auth.get());  // and a policy we can ask about
}

PolkitAuthenticator::PolkitAuthenticator(bool allow_interaction)
    : allow_interaction_(allow_interaction) {}

Authorization PolkitAuthenticator::authorize(std::string_view service, std::string_view reason) {
  ErrorPtr err;
  AuthorityPtr auth = authority(err);
  if (!auth) return Authorization::Unavailable;

  // "Cannot ask" — must degrade to the next tier, not lock the user out.
  if (!actionRegistered(auth.get())) return Authorization::Unavailable;

  SubjectPtr subject = selfSubject();
  if (!subject) return Authorization::Unavailable;

  // Shown in the polkit dialog. Never a secret — the service name and the reason
  // are both caller-supplied labels, and the secret itself never reaches here.
  std::unique_ptr<PolkitDetails, GObjectDeleter> details(polkit_details_new());
  if (details) {
    polkit_details_insert(details.get(), "polkit.message",
                          (std::string(reason) + " (" + std::string(service) + ")").c_str());
  }

  const PolkitCheckAuthorizationFlags flags =
      allow_interaction_ ? POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
                         : POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;

  GError* raw = nullptr;
  ResultPtr result(polkit_authority_check_authorization_sync(
      auth.get(), subject.get(), kPolkitActionId, details.get(), flags, nullptr, &raw));
  ErrorPtr checkErr(raw);

  if (!result) {
    // A cancelled interaction is the user's decision and is reported as an
    // error, not a result. Anything else here is a broken authority, which is a
    // "cannot ask" — not a refusal.
    if (checkErr && g_error_matches(checkErr.get(), G_IO_ERROR, G_IO_ERROR_CANCELLED))
      return Authorization::Cancelled;
    return Authorization::Unavailable;
  }

  if (polkit_authorization_result_get_is_authorized(result.get())) return Authorization::Allowed;

  // A challenge means authentication is *required and possible*, but nothing
  // answered it — no agent registered, or a headless session. Treating that as
  // Denied would strand the caller with no way forward, so it degrades.
  if (polkit_authorization_result_get_is_challenge(result.get())) return Authorization::Unavailable;

  return Authorization::Denied;
}

}  // namespace keyward

#endif  // __linux__ && KEYWARD_HAVE_POLKIT
