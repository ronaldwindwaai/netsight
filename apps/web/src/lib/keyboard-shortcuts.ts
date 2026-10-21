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
  readonly defaultPrevented?: boolean;
  readonly target: unknown;
}

const MODAL_SELECTOR = '[aria-modal="true"], dialog[open]';
const TYPING_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);

/** True when keystrokes are meant for text entry, so a single-key shortcut must not fire. */
export function isTypingTarget(target: unknown): boolean {
  if (typeof target !== 'object' || target === null) return false;
  const { tagName, isContentEditable } = target as ShortcutTarget;
  if (isContentEditable === true) return true;
  return typeof tagName === 'string' && TYPING_TAGS.has(tagName.toUpperCase());
}

/** True when the target sits inside an open modal, which must keep focus to itself. */
function isInsideModal(target: unknown): boolean {
  if (typeof target !== 'object' || target === null) return false;
  const { closest } = target as ShortcutTarget;
  return typeof closest === 'function' && closest.call(target, MODAL_SELECTOR) !== null;
}

/**
 * True for a bare "/" typed outside any text field: the conventional "focus search" shortcut.
 * Modified keys (browser and OS shortcuts), IME composition, already-handled events and keys
 * pressed inside an open modal are ignored.
 */
export function isFocusSearchShortcut(event: ShortcutEvent): boolean {
  if (event.key !== '/') return false;
  if (event.ctrlKey || event.metaKey || event.altKey) return false;
  if (event.isComposing === true || event.defaultPrevented === true) return false;
  return !isTypingTarget(event.target) && !isInsideModal(event.target);
}
