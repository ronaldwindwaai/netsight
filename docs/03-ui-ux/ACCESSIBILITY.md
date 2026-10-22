# Accessibility

Target WCAG 2.2 AA where practical.

Requirements:
- keyboard navigation;
- visible focus;
- semantic labels;
- colour-independent severity meaning;
- sufficient contrast;
- reduced motion support;
- accessible tables/forms;
- chart summaries/table alternatives;
- screen-reader status text;
- error messages linked to controls.

## Keyboard shortcuts and page titles

- Pressing `/` outside a text field, dialog or modifier combination focuses the page finder
  in the top bar. The shortcut is advertised by a visible keycap (hidden on touch devices and
  narrow screens), `aria-keyshortcuts` on the input and the input's description. Escape closes
  the result list; there are no other single-key shortcuts. Holding the key (auto-repeat) does
  nothing, and the box's existing text is selected on focus so typing replaces it.
- WCAG 2.1.4 (Character Key Shortcuts): `/` is a bare-key shortcut with no on-screen way to remap
  it, so it relies on the "can be turned off" route. Setting `localStorage['netsight.shortcuts']`
  to `off` disables it (read in a try/catch; blocked storage leaves it on). It is also inactive in
  text fields (including `role=textbox|combobox|searchbox`), dialogs, with modifier keys and during
  IME composition, so it cannot fire while someone is dictating or typing. Known gap: there is no
  settings UI for the toggle yet; until one exists the key is set through browser storage.
- Every dashboard screen sets a static page name through Next.js metadata
  (`export const metadata = { title: '...' }`), rendered as `Page · Netsight`
  (WCAG 2.4.2). `src/lib/page-titles.test.ts` fails when a page omits it.
- Focus rings use `--netsight-focus` (a theme-aware blue), including on Bootstrap controls that
  otherwise swap the outline for a low-contrast shadow.
- Loading states are a single polite status region over a skeleton (`LoadingState`); failures
  that may clear (source unavailable, rate limited, maintenance, invalid response) offer
  "Try again", which re-renders the screen in place.
