#include "keyward/tui_prompter.hpp"

#include <cstddef>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <string>
#include <vector>

namespace keyward {

std::string tui_prompt_title(PromptReason reason, std::string_view service) {
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

bool TuiPrompter::collect(std::string_view service, PromptReason reason,
                          std::vector<PromptField>& fields) {
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
  if (!confirmed) return false;

  for (std::size_t i = 0; i < fields.size(); ++i) fields[i].value = values[i];
  return true;
}

}  // namespace keyward
