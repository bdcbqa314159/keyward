#pragma once
#include <cstddef>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "keyward/prompter.hpp"

// An FTXUI reference implementation of the Prompter contract: one input per
// schema field (masked for sensitive ones), Save / Cancel, Esc cancels.
//
// HEADER-ONLY ON PURPOSE. This is ~100 lines adapting to somebody else's UI
// library, and the only application that wants it is one that already links
// FTXUI — so compiling it here, in your translation unit, against *your* FTXUI is
// the whole point:
//
//   - no second copy of FTXUI in the binary (two versions of a header-heavy C++
//     library in one program is an ODR hazard, and a silent one);
//   - no version pin from us — it builds against whatever FTXUI you have;
//   - no ABI fragility from a prebuilt archive compiled with our flags and our
//     standard version;
//   - nothing extra to install or link. Including this header is the integration.
//
// You supply FTXUI (`libftxui-dev` on Debian/Ubuntu, or your own FetchContent).
// keyward does not bring it.
//
// The same shape is the answer for any other toolkit: a Qt or ImGui prompter
// would also be a header you compile against your own stack. keyward ships the
// contract (prompter.hpp) plus reference implementations; the toolkit is yours.
//
// CONTRACT NOTE: this runs its own modal FTXUI loop inside collect(), so the host
// application must cede the terminal for the duration of the call. An app already
// inside its own ScreenInteractive::Loop cannot nest this one. See prompter.hpp
// for the full obligations, and keyward/testing/conformance.hpp to check your own
// implementation if you write one.
namespace keyward {

// The title line shown above the form. Free function so it stays unit-testable
// without a terminal — the form itself is interactive and is not.
inline std::string tui_prompt_title(PromptReason reason, std::string_view service) {
  const std::string svc(service);
  switch (reason) {
    case PromptReason::Missing:
      return "Set up credentials for " + svc;
    case PromptReason::Invalid:
      return "Update rejected credentials for " + svc;
    case PromptReason::Corrupt:
      return "Re-enter unreadable credentials for " + svc;
  }
  return svc;
}

class TuiPrompter : public Prompter {
 public:
  bool collect(std::string_view service, PromptReason reason,
               std::vector<PromptField>& fields) override {
    using namespace ftxui;

    auto screen = ScreenInteractive::TerminalOutput();

    // Bound storage for each input, pre-filled from the field's current value.
    // Sized up front so the &values[i] pointers below stay valid.
    std::vector<std::string> values;
    values.reserve(fields.size());
    for (const PromptField& f : fields) values.push_back(f.value);

    std::vector<Component> inputs;
    for (std::size_t i = 0; i < fields.size(); ++i) {
      InputOption opt = InputOption::Default();
      opt.password = fields[i].sensitive;  // mask secret fields
      inputs.push_back(Input(&values[i], fields[i].name, opt));
    }

    bool confirmed = false;
    auto save = Button("Save", [&] {
      confirmed = true;
      screen.Exit();
    });
    auto cancel = Button("Cancel", [&] {
      confirmed = false;
      screen.Exit();
    });

    auto form = Container::Vertical({});
    for (Component& in : inputs) form->Add(in);
    form->Add(Container::Horizontal({save, cancel}));

    auto renderer = Renderer(form, [&] {
      Elements rows;
      rows.push_back(text(tui_prompt_title(reason, service)) | bold);
      rows.push_back(separator());
      for (std::size_t i = 0; i < fields.size(); ++i) {
        rows.push_back(hbox({
            text(fields[i].name + ": ") | size(WIDTH, EQUAL, 14),
            inputs[i]->Render() | flex,
        }));
      }
      rows.push_back(separator());
      rows.push_back(hbox({save->Render(), text("  "), cancel->Render()}));
      return vbox(std::move(rows)) | border;
    });

    renderer |= CatchEvent([&](Event e) {
      if (e == Event::Escape) {
        confirmed = false;
        screen.Exit();
        return true;
      }
      return false;
    });

    screen.Loop(renderer);
    if (!confirmed) return false;  // contract: shape untouched, SDK stores nothing

    for (std::size_t i = 0; i < fields.size(); ++i) fields[i].value = values[i];
    return true;
  }
};

}  // namespace keyward
