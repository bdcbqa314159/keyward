// Runs the shipped conformance suite against keyward's own reference
// implementations, and against deliberately non-conforming ones.
//
// Both halves matter. The first proves our references actually satisfy the
// contract we hand to integrators — if `CliPrompter` cannot pass, the contract is
// wrong or the reference is. The second proves the suite has teeth: a checker
// that never fails would let a broken prompt window ship with a green tick.
#include "keyward/testing/conformance.hpp"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <vector>

#include "keyward/authenticator.hpp"
#include "keyward/cli_prompter.hpp"
#include "keyward/prompter.hpp"

using keyward::Authorization;
using keyward::PromptField;
using keyward::PromptReason;
using namespace keyward::testing;

namespace {

std::vector<PromptField> schemaFields() { return {{"email", false, ""}, {"token", true, ""}}; }

// --- deliberately broken gatherers, to prove the checks bite -----------------

// Drops a field — the SDK maps values back by position, so this corrupts records.
class DropsAFieldPrompter : public keyward::Prompter {
 public:
  bool collect(std::string_view, PromptReason, std::vector<PromptField>& fields) override {
    if (!fields.empty()) fields.pop_back();
    return true;
  }
};

// Decides for itself that a field is not sensitive.
class RewritesSensitivityPrompter : public keyward::Prompter {
 public:
  bool collect(std::string_view, PromptReason, std::vector<PromptField>& fields) override {
    for (PromptField& f : fields) f.sensitive = false;
    return true;
  }
};

}  // namespace

// --- the references must conform --------------------------------------------

TEST(Conformance, CliPrompterAcceptsConformingly) {
  std::istringstream in("a@b.com\ns3cr3t\n");
  std::ostringstream out;
  keyward::CliPrompter prompter(in, out);

  const std::vector<PromptField> before = schemaFields();
  std::vector<PromptField> after = before;
  ASSERT_TRUE(prompter.collect("jira", PromptReason::Missing, after));

  const ConformanceReport r = check_accepted(before, after);
  EXPECT_TRUE(r.conforms()) << "keyward's own CLI reference violates the contract:\n"
                            << r.summary();
  EXPECT_EQ(after[0].value, "a@b.com");
  EXPECT_EQ(after[1].value, "s3cr3t");
}

TEST(Conformance, CliPrompterCancelsConformingly) {
  std::istringstream in("");  // EOF immediately — Ctrl-D
  std::ostringstream out;
  keyward::CliPrompter prompter(in, out);

  const std::vector<PromptField> before = schemaFields();
  std::vector<PromptField> after = before;
  ASSERT_FALSE(prompter.collect("jira", PromptReason::Missing, after));

  const ConformanceReport r = check_cancelled(before, after);
  EXPECT_TRUE(r.conforms()) << r.summary();
}

TEST(Conformance, NoAuthConformsWhenItCanAnswer) {
  keyward::NoAuth auth;
  // NoAuth always can answer, so the "refused" check is the applicable one only
  // in the sense that it must never report Unavailable.
  EXPECT_EQ(auth.authorize("jira", "read"), Authorization::Allowed);
}

// --- the suite must have teeth ----------------------------------------------

TEST(Conformance, CatchesAGathererThatDropsAField) {
  DropsAFieldPrompter prompter;
  const std::vector<PromptField> before = schemaFields();
  std::vector<PromptField> after = before;
  ASSERT_TRUE(prompter.collect("jira", PromptReason::Missing, after));

  const ConformanceReport r = check_accepted(before, after);
  ASSERT_FALSE(r.conforms()) << "a dropped field slipped past the checker";
  EXPECT_NE(r.summary().find("field count changed"), std::string::npos) << r.summary();
}

TEST(Conformance, CatchesAGathererThatRewritesSensitivity) {
  RewritesSensitivityPrompter prompter;
  const std::vector<PromptField> before = schemaFields();
  std::vector<PromptField> after = before;
  ASSERT_TRUE(prompter.collect("jira", PromptReason::Missing, after));

  const ConformanceReport r = check_accepted(before, after);
  ASSERT_FALSE(r.conforms()) << "a rewritten sensitive flag slipped past the checker";
  EXPECT_NE(r.summary().find("sensitive flag"), std::string::npos) << r.summary();
}

// The mistake the contract exists to prevent, and the one PolkitAuthenticator
// had to be designed carefully to avoid.
TEST(Conformance, CatchesDeniedUsedForCouldNotAsk) {
  const ConformanceReport r = check_authenticator_when_unavailable(Authorization::Denied);
  ASSERT_FALSE(r.conforms());
  EXPECT_NE(r.summary().find("stranded"), std::string::npos) << r.summary();
}

TEST(Conformance, CatchesUnavailableUsedForARefusal) {
  const ConformanceReport r = check_authenticator_when_refused(Authorization::Unavailable);
  ASSERT_FALSE(r.conforms());
  EXPECT_NE(r.summary().find("override the refusal"), std::string::npos) << r.summary();
}

TEST(Conformance, CatchesAllowedFromAMechanismThatAskedNobody) {
  const ConformanceReport r = check_authenticator_when_unavailable(Authorization::Allowed);
  ASSERT_FALSE(r.conforms());
  EXPECT_NE(r.summary().find("asked no one"), std::string::npos) << r.summary();
}

TEST(Conformance, AcceptsUnavailableWhenNothingCouldBeAsked) {
  EXPECT_TRUE(check_authenticator_when_unavailable(Authorization::Unavailable).conforms());
  EXPECT_TRUE(check_authenticator_when_unavailable(Authorization::Cancelled).conforms());
}
