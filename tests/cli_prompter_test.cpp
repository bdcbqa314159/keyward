// Task 8 — the CLI prompter. Streams are injected (istringstream/ostringstream),
// so no terminal is needed and no-echo masking is simply skipped.
#include "keyward/cli_prompter.hpp"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <vector>

#include "keyward/prompter.hpp"

using keyward::CliPrompter;
using keyward::PromptField;
using keyward::PromptReason;

namespace {
std::vector<PromptField> demo_fields() {
  return {{"email", false, ""}, {"url", false, ""}, {"token", true, ""}};
}
}  // namespace

TEST(CliPrompter, CollectsAllFieldsInOrder) {
  std::istringstream in("a@b.com\nhttps://x\ntok\n");
  std::ostringstream out;
  CliPrompter p(in, out);
  auto fields = demo_fields();
  ASSERT_TRUE(p.collect("jira", PromptReason::Missing, fields));
  EXPECT_EQ(fields[0].value, "a@b.com");
  EXPECT_EQ(fields[1].value, "https://x");
  EXPECT_EQ(fields[2].value, "tok");
}

TEST(CliPrompter, EmptyLineKeepsPrefill) {
  std::istringstream in("\n\nnew\n");  // keep email, keep url, change token
  std::ostringstream out;
  CliPrompter p(in, out);
  std::vector<PromptField> fields{
      {"email", false, "e"}, {"url", false, "u"}, {"token", true, "old"}};
  ASSERT_TRUE(p.collect("jira", PromptReason::Invalid, fields));
  EXPECT_EQ(fields[0].value, "e");
  EXPECT_EQ(fields[1].value, "u");
  EXPECT_EQ(fields[2].value, "new");
}

TEST(CliPrompter, EofBeforeAllFieldsCancels) {
  std::istringstream in("a@b.com\n");  // one line, then EOF, but three fields
  std::ostringstream out;
  CliPrompter p(in, out);
  auto fields = demo_fields();
  EXPECT_FALSE(p.collect("jira", PromptReason::Missing, fields));
}

TEST(CliPrompter, HeaderReflectsReason) {
  std::istringstream in("a\nb\nc\n");
  std::ostringstream out;
  CliPrompter p(in, out);
  auto fields = demo_fields();
  p.collect("jira", PromptReason::Invalid, fields);
  EXPECT_NE(out.str().find("rejected"), std::string::npos);
  EXPECT_NE(out.str().find("jira"), std::string::npos);
}
