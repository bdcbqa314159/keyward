#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace keyward {

// Why the SDK is asking for a credential — lets a gatherer tailor its message
// ("set up X" vs "X was rejected — update it").
enum class PromptReason {
  Missing,  // nothing stored yet — first-time setup
  Invalid,  // stored, but the app's service rejected it — update
  Corrupt,  // stored bytes couldn't be parsed — re-enter
};

// One field to collect, described from the record's schema. `value` carries the
// current value IN (empty when creating) and the entered value OUT.
struct PromptField {
  std::string name;   // stored field name / label
  bool sensitive;     // mask the input; treat as a secret
  std::string value;  // prefill in, collected out
};

// The contract a credential gatherer implements — CLI, TUI, GUI, env, etc. The
// SDK builds `fields` from the record's schema and passes it in; the
// implementation fills each `value` and returns true, or returns false to
// cancel. A gatherer never touches storage, crypto, or the OS keychain — it only
// collects values, which is itself a safety boundary.
class Prompter {
 public:
  virtual ~Prompter() = default;
  virtual bool collect(std::string_view service, PromptReason reason,
                       std::vector<PromptField>& fields) = 0;
};

}  // namespace keyward
