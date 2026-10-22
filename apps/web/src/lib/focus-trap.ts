/**
 * Where Tab (or Shift+Tab) should land inside a focus trap of `count` focusable elements when focus
 * is on `index` (-1 when focus is outside the trap). Wraps at both ends; -1 means nothing to focus.
 */
export function trapIndex(count: number, index: number, backwards: boolean): number {
  if (count <= 0) return -1;
  if (index < 0) return backwards ? count - 1 : 0;
  return (index + (backwards ? count - 1 : 1)) % count;
}
