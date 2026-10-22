/** The subset of an event target the shortcut guard needs; satisfied by any DOM element. */
export interface ShortcutTarget {
  readonly tagName?: string;
  readonly isContentEditable?: boolean;
  readonly closest?: (selector: string) => unknown;
}

/** The subset of a keyboard event the shortcut check needs; satisfied by KeyboardEvent. */
export interface ShortcutEvent {
  readonly key: string;
  readonly ctrlKey: boolean;
  readonly metaKey: boolean;
  readonly altKey: boolean;
  readonly isComposing?: boolean;
  readonly repeat?: boolean;
  readonly defaultPrevented?: boolean;
  readonly target: unknown;
}

const MODAL_SELECTOR = '[aria-modal="true"], dialog[open]';
const TYPING_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);
/** ARIA text-entry widgets (custom comboboxes, rich editors) that are not native form controls. */
const TYPING_ROLE_SELECTOR = '[role="textbox"], [role="combobox"], [role="searchbox"]';

/** True when keystrokes are meant for text entry, so a single-key shortcut must not fire. */
export function isTypingTarget(target: unknown): boolean {
  if (typeof target !== 'object' || target === null) return false;
  const { tagName, isContentEditable } = target as ShortcutTarget;
  if (isContentEditable === true) return true;
  if (typeof tagName === 'string' && TYPING_TAGS.has(tagName.toUpperCase())) return true;
  const { closest } = target as ShortcutTarget;
  return typeof closest === 'function' && closest.call(target, TYPING_ROLE_SELECTOR) !== null;
}

/** True when the target sits inside an open modal, which must keep focus to itself. */
function isInsideModal(target: unknown): boolean {
  if (typeof target !== 'object' || target === null) return false;
  const { closest } = target as ShortcutTarget;
  return typeof closest === 'function' && closest.call(target, MODAL_SELECTOR) !== null;
}

/**
 * True for a bare "/" typed outside any text field: the conventional "focus search" shortcut.
 * Modified keys (browser and OS shortcuts), IME composition, held-down key repeats, already-handled events and keys
 * pressed inside an open modal are ignored.
 */
export function isFocusSearchShortcut(event: ShortcutEvent): boolean {
  if (event.key !== '/') return false;
  if (event.ctrlKey || event.metaKey || event.altKey) return false;
  if (event.isComposing === true || event.defaultPrevented === true || event.repeat === true) return false;
  return !isTypingTarget(event.target) && !isInsideModal(event.target);
}

/** localStorage key that turns the bare-key shortcut off when its value is "off" (WCAG 2.1.4). */
export const SHORTCUTS_STORAGE_KEY = 'netsight.shortcuts';

/** The subset of Storage the preference check needs. */
export interface ShortcutPreferenceStore {
  getItem(key: string): string | null;
}

/**
 * Whether the bare-key shortcut is enabled. On by default; any storage failure (blocked storage,
 * private windows, no storage) leaves it on rather than breaking the page.
 */
export function areShortcutsEnabled(store?: ShortcutPreferenceStore): boolean {
  try {
    return (store ?? globalThis.localStorage).getItem(SHORTCUTS_STORAGE_KEY) !== 'off';
  } catch {
    return true;
  }
}
