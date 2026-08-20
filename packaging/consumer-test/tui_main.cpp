// Proves the integration path a real FTXUI application takes: include the
// header-only prompter and compile it against YOUR OWN FTXUI, with no keyward
// TUI library to find or link.
//
// CI builds this against an FTXUI built SEPARATELY from keyward's own build tree,
// because that separateness is the claim being tested: the consumer's FTXUI is
// the one that ends up in the binary, and no keyward TUI library is linked.
//
// It does not run the interactive form (a CI runner has no terminal). Compiling
// and linking is the assertion; the form's behaviour is covered by keyward's own
// tui_prompter tests.
#include <cstdio>
#include <string>
#include <vector>

#include "keyward/prompter.hpp"
#include "keyward/tui_prompter.hpp"
#include "keyward/vault.hpp"

int main() {
  keyward::TuiPrompter prompter;

  // The title helper is pure, so it can be checked without a terminal.
  const std::string title = keyward::tui_prompt_title(keyward::PromptReason::Missing, "jira");
  if (title.find("jira") == std::string::npos) return 1;

  // A TuiPrompter must be usable wherever the SDK wants a Prompter.
  keyward::Prompter& as_contract = prompter;
  (void)as_contract;

  std::printf("header-only TUI prompter built against the system FTXUI\n");
  return 0;
}
