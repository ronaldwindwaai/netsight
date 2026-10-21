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
  IME composition, so it cannot fire while someone is dictating or typing. The toggle is the "Keyboard shortcuts" switch on the Preferences page
  (account menu > Preferences), which writes the same key.
- Every dashboard screen sets a static page name through Next.js metadata
  (`export const metadata = { title: '...' }`), rendered as `Page · Netsight`
  (WCAG 2.4.2). `src/lib/page-titles.test.ts` fails when a page omits it.
- Focus rings use `--netsight-focus` (a theme-aware blue), including on Bootstrap controls that
  otherwise swap the outline for a low-contrast shadow.
- Loading states are a single polite status region over a skeleton (`LoadingState`); failures
  that may clear (source unavailable, rate limited, maintenance, invalid response) offer
  "Try again", which re-renders the screen in place.

## Preferences, mobile drawer and first run

- **Preferences** (`/preferences`, from the account menu) are client-only and stored in `localStorage`
  (`netsight.shortcuts`, `netsight.density`, `netsight.page_size`) inside try/catch; with storage blocked the
  controls still work for the page view and the panel says so. Nothing is sent to the API. Defaults are removed
  from storage. Table density is applied to `<html data-density>` by a tiny `beforeInteractive` script so rows do not
  jump on load. The default list size is applied only when a list address has no `page_size`: the list controls swap
  it in once with `router.replace`; a `page_size` in the URL always wins, and while a non-default size is preferred
  the size links keep `page_size` explicit so choosing the built-in 50 is respected. It is parsed by the existing
  `parsePageParams`. Known limit: the server renders the first response at the built-in size, so a reader with a
  different preference sees one extra load on first arrival at a list.
- **Navigation drawer (below 992px):** `MobileDrawer` names the toggle ("Open/Close navigation menu",
  `aria-expanded`, `aria-controls`), moves focus into the drawer on open and back to the toggle on close, keeps Tab
  inside the drawer, closes on Escape and after navigation, and makes the closed drawer and (while open) the page
  behind it `inert`. Top-bar controls are 44 x 44 on touch devices, and `scroll-padding` keeps anchors and focused
  controls clear of the fixed header and the phone tab bar.
- **First run:** when the device source answers "not configured", the overview shows a checklist of read-only
  sources (LibreNMS first) with status as text, the API settings to set (names only), the integration guide path and
  the in-app page, instead of an error alert.
