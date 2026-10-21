import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { isFocusSearchShortcut, isTypingTarget } from './keyboard-shortcuts.ts';

const press = (over: Record<string, unknown> = {}) => ({
  key: '/',
  ctrlKey: false,
  metaKey: false,
  altKey: false,
  target: { tagName: 'BODY' },
  ...over,
});

describe('isTypingTarget', () => {
  it('treats text controls and editable regions as typing', () => {
    for (const tagName of ['INPUT', 'textarea', 'Select']) assert.equal(isTypingTarget({ tagName }), true);
    assert.equal(isTypingTarget({ tagName: 'DIV', isContentEditable: true }), true);
  });

  it('does not treat buttons, links, the body or non-objects as typing', () => {
    for (const tagName of ['BUTTON', 'A', 'BODY']) assert.equal(isTypingTarget({ tagName }), false);
    assert.equal(isTypingTarget(null), false);
    assert.equal(isTypingTarget(undefined), false);
    assert.equal(isTypingTarget('INPUT'), false);
  });
});

describe('isFocusSearchShortcut', () => {
  it('accepts a bare slash outside text fields', () => {
    assert.equal(isFocusSearchShortcut(press()), true);
    assert.equal(isFocusSearchShortcut(press({ target: { tagName: 'BUTTON' } })), true);
  });

  it('ignores other keys', () => {
    assert.equal(isFocusSearchShortcut(press({ key: 'a' })), false);
    assert.equal(isFocusSearchShortcut(press({ key: '?' })), false);
  });

  it('ignores modified slashes so browser and OS shortcuts keep working', () => {
    for (const mod of ['ctrlKey', 'metaKey', 'altKey']) {
      assert.equal(isFocusSearchShortcut(press({ [mod]: true })), false);
    }
  });

  it('ignores a slash typed into a field, during composition, or already handled', () => {
    assert.equal(isFocusSearchShortcut(press({ target: { tagName: 'INPUT' } })), false);
    assert.equal(isFocusSearchShortcut(press({ isComposing: true })), false);
    assert.equal(isFocusSearchShortcut(press({ defaultPrevented: true })), false);
  });

  it('ignores a slash pressed inside an open modal so focus cannot escape it', () => {
    const inModal = { tagName: 'BUTTON', closest: (selector: string) => (selector.includes('aria-modal') ? {} : null) };
    const outside = { tagName: 'BUTTON', closest: () => null };
    assert.equal(isFocusSearchShortcut(press({ target: inModal })), false);
    assert.equal(isFocusSearchShortcut(press({ target: outside })), true);
  });
});
