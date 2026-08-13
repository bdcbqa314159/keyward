// Task 9 — the FTXUI TUI prompter. The form is interactive (a real terminal
// event loop), so it can't be driven headless like the CLI's injected streams.
// We test the non-interactive parts: the title logic, and that TuiPrompter links
// and satisfies the Prompter interface. CI proves it *compiles* on all 3 OSes.
#include "keyward/tui_prompter.hpp"

#include <gtest/gtest.h>

#include <string>

#include "keyward/prompter.hpp"

using keyward::PromptReason;
using keyward::TuiPrompter;

TEST(TuiPrompter, TitleReflectsReasonAndService) {
  EXPECT_NE(keyward::tui_prompt_title(PromptReason::Missing, "jira").find("Set up"),
            std::string::npos);
  EXPECT_NE(keyward::tui_prompt_title(PromptReason::Invalid, "jira").find("Update"),
            std::string::npos);
  EXPECT_NE(keyward::tui_prompt_title(PromptReason::Corrupt, "jira").find("Re-enter"),
            std::string::npos);
  EXPECT_NE(keyward::tui_prompt_title(PromptReason::Missing, "jira").find("jira"),
            std::string::npos);
}

TEST(TuiPrompter, SatisfiesPrompterInterface) {
  TuiPrompter tui;
  keyward::Prompter* base = &tui;  // links + is-a Prompter (collect is interactive; not run here)
  EXPECT_NE(base, nullptr);
}
