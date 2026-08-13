#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "keyward/prompter.hpp"

namespace keyward {

// The title line shown above the form for a given reason. Factored out so it's
// unit-testable without a terminal (the form itself is interactive).
std::string tui_prompt_title(PromptReason reason, std::string_view service);

// An FTXUI form Prompter: one input per schema field (masked for Sensitive
// fields), with Save / Cancel (Esc also cancels). Part of the optional
// `keyward::tui` component — core consumers that don't want a TUI never link it,
// and FTXUI stays a private implementation detail (not in this header).
class TuiPrompter : public Prompter {
 public:
  bool collect(std::string_view service, PromptReason reason,
               std::vector<PromptField>& fields) override;
};

}  // namespace keyward
