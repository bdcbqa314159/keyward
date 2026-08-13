#pragma once
#include <iosfwd>
#include <string_view>
#include <vector>

#include "keyward/prompter.hpp"

namespace keyward {

// A terminal Prompter: reads each field on stdin, suppressing echo for Sensitive
// fields on a real console. The I/O streams are injectable (default std::cin /
// std::cout) so it's testable without a tty. Part of the optional `keyward::cli`
// component — core consumers that don't want a CLI never link it.
class CliPrompter : public Prompter {
 public:
  CliPrompter();  // std::cin / std::cout
  CliPrompter(std::istream& in, std::ostream& out);

  bool collect(std::string_view service, PromptReason reason,
               std::vector<PromptField>& fields) override;

 private:
  std::istream& in_;
  std::ostream& out_;
};

}  // namespace keyward
