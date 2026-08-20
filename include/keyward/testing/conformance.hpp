#pragma once
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "keyward/authenticator.hpp"
#include "keyward/prompter.hpp"

// Conformance checks for the contracts an integrating application implements.
//
// The contracts in prompter.hpp and authenticator.hpp are not negotiable, and a
// rule nobody can check is only an expectation. This header is the checkable
// half: an application implements its own prompt window or authenticator, runs
// these against it, and finds out whether it conforms before shipping.
//
// Deliberately framework-agnostic — no gtest, no macros, no exceptions. It
// returns a report you assert on in whatever test framework you already use, and
// it works from a language binding where our C++ test setup is unavailable.
//
// A prompter is interactive by nature, so this cannot drive an arbitrary UI. The
// split is: YOU exercise your prompter however you like (scripted input, a fake
// event source, a hand-driven run), then hand the before/after state here and
// these functions judge it. That keeps the checks honest about what can be
// automated.
namespace keyward::testing {

struct Violation {
  std::string rule;    // which obligation was broken, quoting the header
  std::string detail;  // what was observed
};

class ConformanceReport {
 public:
  void fail(std::string rule, std::string detail) {
    violations_.push_back({std::move(rule), std::move(detail)});
  }
  void absorb(const ConformanceReport& other) {
    violations_.insert(violations_.end(), other.violations_.begin(), other.violations_.end());
  }
  bool conforms() const { return violations_.empty(); }
  const std::vector<Violation>& violations() const { return violations_; }

  // One line per violation, suitable for a test failure message.
  std::string summary() const {
    if (violations_.empty()) return "conforms";
    std::string out;
    for (const Violation& v : violations_) out += "  [" + v.rule + "] " + v.detail + "\n";
    return out;
  }

 private:
  std::vector<Violation> violations_;
};

namespace detail {

inline ConformanceReport check_shape(const std::vector<PromptField>& before,
                                     const std::vector<PromptField>& after) {
  ConformanceReport r;
  if (before.size() != after.size()) {
    r.fail("Prompter MUST 2 (size)", "field count changed from " + std::to_string(before.size()) +
                                         " to " + std::to_string(after.size()) +
                                         "; the SDK maps values back by position");
    return r;  // per-index checks below would be meaningless
  }
  for (std::size_t i = 0; i < before.size(); ++i) {
    if (before[i].name != after[i].name) {
      r.fail("Prompter MUST 2 (order/name)", "field " + std::to_string(i) + " was '" +
                                                 before[i].name + "', came back as '" +
                                                 after[i].name + "'");
    }
    if (before[i].sensitive != after[i].sensitive) {
      r.fail("Prompter MUST 3 (sensitivity)",
             "field '" + before[i].name +
                 "' had its sensitive flag changed; it comes from the "
                 "schema, not from the gatherer");
    }
  }
  return r;
}

}  // namespace detail

// Judge a collect() that returned TRUE.
//
// `before` is the vector as the SDK handed it over; `after` is the same vector
// once your prompter returned. Values themselves are not judged — an empty
// value, or an untouched prefill, are both legitimate things to store.
inline ConformanceReport check_accepted(const std::vector<PromptField>& before,
                                        const std::vector<PromptField>& after) {
  return detail::check_shape(before, after);
}

// Judge a collect() that returned FALSE.
//
// The SDK stores nothing and wipes the vector, so the only obligation that
// survives cancellation is that the shape is intact — a caller may retry with
// the same vector, and a mangled one would corrupt the retry.
inline ConformanceReport check_cancelled(const std::vector<PromptField>& before,
                                         const std::vector<PromptField>& after) {
  return detail::check_shape(before, after);
}

// Judge an authenticator without needing a user.
//
// `available` is your own answer to "could this mechanism ask right now?" — the
// equivalent of polkit_available() or biometric_available(). The check that
// matters is the one that strands users: when nothing can be asked, the answer
// must be Unavailable, because that is the only value a FallbackAuthenticator
// will degrade on.
inline ConformanceReport check_authenticator_when_unavailable(Authorization answer) {
  ConformanceReport r;
  if (answer == Authorization::Denied) {
    r.fail("Authenticator MUST 1",
           "returned Denied when it could not ask. Denied means the user refused, and a "
           "FallbackAuthenticator will NOT try the next tier — the user is stranded. Return "
           "Unavailable instead.");
  } else if (answer == Authorization::Allowed) {
    r.fail("Authenticator (fail closed)",
           "returned Allowed when it could not ask anybody. Access must never be granted by "
           "a mechanism that asked no one.");
  }
  return r;
}

// Judge an authenticator that CAN ask and was refused. A refusal must stand:
// reporting Unavailable here lets a weaker tier override the user's "no".
inline ConformanceReport check_authenticator_when_refused(Authorization answer) {
  ConformanceReport r;
  if (answer == Authorization::Unavailable) {
    r.fail("Authenticator MUST 1 (inverse)",
           "returned Unavailable after the user refused. That lets a FallbackAuthenticator "
           "ask a weaker tier and override the refusal. Return Denied or Cancelled.");
  } else if (answer == Authorization::Allowed) {
    r.fail("Authenticator (fail closed)", "returned Allowed after a refusal");
  }
  return r;
}

}  // namespace keyward::testing
