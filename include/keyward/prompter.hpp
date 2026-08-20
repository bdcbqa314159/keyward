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

// The contract a credential gatherer implements — CLI, TUI, GUI, env, etc.
//
// THIS CONTRACT IS NOT NEGOTIABLE. keyward decides what is asked for; an
// integrating application implements the window that asks it. The SDK builds
// `fields` from the record's schema — one entry per field, in schema order, with
// `sensitive` set from the schema — and hands it over. Conformance is checkable:
// see keyward/testing/conformance.hpp, which is shipped for exactly this purpose.
//
// An implementation MUST:
//
//  1. Return true only when `fields` holds the values to store; return false to
//     cancel, and the SDK stores nothing.
//  2. Leave the vector's SIZE, ORDER and `name`s untouched. The SDK maps values
//     back by position. Adding, removing or reordering entries corrupts the
//     record.
//  3. Leave each `sensitive` flag untouched — it comes from the schema, not from
//     the gatherer's judgement.
//  4. Mask input for fields with `sensitive == true`, and never echo them.
//  5. Never persist, log, transmit or copy collected values anywhere. A gatherer
//     touches no storage, no crypto and no keychain; that narrowness is itself a
//     safety boundary.
//  6. Not throw. If it cannot proceed, return false. The SDK does not catch.
//  7. Tolerate an empty `fields` vector (return true; there is nothing to ask).
//
// An implementation MAY:
//
//  - Block. `collect` is called synchronously and the SDK does nothing until it
//    returns. A TUI or GUI gatherer is expected to run its own modal loop here
//    and restore the terminal or window state before returning. (keyward's own
//    FTXUI reference does exactly this, and assumes the host application cedes
//    the terminal for the duration of the call.)
//  - Treat a non-empty incoming `value` as a default to offer the user; whatever
//    is left in it when returning true is what gets stored.
//
// The SDK guarantees, in return:
//
//  - `service` and every `name` are safe to display. A `value` never is.
//  - `fields` is wiped after `collect` returns, on EVERY path including
//    cancellation — so a gatherer need not scrub the vector itself.
//  - `collect` is never called concurrently on the same instance.
class Prompter {
 public:
  virtual ~Prompter() = default;
  virtual bool collect(std::string_view service, PromptReason reason,
                       std::vector<PromptField>& fields) = 0;
};

}  // namespace keyward
