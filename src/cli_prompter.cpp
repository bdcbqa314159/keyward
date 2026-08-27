#include "keyward/cli_prompter.hpp"

#include <iostream>
#include <string>

#include "keyward/secure_memory.hpp"  // secure_zero (L6: wipe gathered secret)

#if defined(_WIN32)
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace keyward {

namespace {

// Read one line from `in`. If `mask` and stdin is an interactive console, echo is
// suppressed (for secrets). On pipes / tests / redirected input it's a plain
// getline — the console toggle self-disables when there's no real terminal.
std::string read_line(std::istream& in, bool mask) {
#if defined(_WIN32)
  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  bool toggled = false;
  if (mask && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
    SetConsoleMode(h, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    toggled = true;
  }
  std::string line;
  std::getline(in, line);
  if (toggled) SetConsoleMode(h, mode);
  return line;
#else
  termios original{};
  bool toggled = false;
  if (mask && ::isatty(STDIN_FILENO) && ::tcgetattr(STDIN_FILENO, &original) == 0) {
    termios masked = original;
    masked.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &masked);
    toggled = true;
  }
  std::string line;
  std::getline(in, line);
  if (toggled) ::tcsetattr(STDIN_FILENO, TCSANOW, &original);
  return line;
#endif
}

}  // namespace

CliPrompter::CliPrompter() : in_(std::cin), out_(std::cout) {}
CliPrompter::CliPrompter(std::istream& in, std::ostream& out) : in_(in), out_(out) {}

bool CliPrompter::collect(std::string_view service, PromptReason reason,
                          std::vector<PromptField>& fields) {
  switch (reason) {
    case PromptReason::Missing:
      out_ << "Set up credentials for '" << service << "':\n";
      break;
    case PromptReason::Invalid:
      out_ << "Credentials for '" << service << "' were rejected - update them:\n";
      break;
    case PromptReason::Corrupt:
      out_ << "Stored credentials for '" << service << "' are unreadable - re-enter:\n";
      break;
  }

  const bool console = (&in_ == &std::cin);
  for (PromptField& f : fields) {
    out_ << "  " << f.name;
    if (!f.sensitive && !f.value.empty()) out_ << " [" << f.value << "]";  // current default
    out_ << ": " << std::flush;

    std::string line = read_line(in_, console && f.sensitive);
    if (console && f.sensitive) out_ << "\n";  // echo the newline the terminal swallowed

    if (line.empty() && in_.eof()) return false;     // Ctrl-D / stream ended -> cancel
    if (line.empty() && !f.value.empty()) continue;  // blank keeps the prefilled value
    f.value = line;
    secure_zero(line.data(), line.size());  // L6: don't leave the gathered secret in this local
  }
  return true;
}

}  // namespace keyward
