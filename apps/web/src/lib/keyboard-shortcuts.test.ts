import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { JSDOM } from 'jsdom';

import { areShortcutsEnabled, isFocusSearchShortcut, isTypingTarget } from './keyboard-shortcuts.ts';

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

  it('treats ARIA textbox, combobox and searchbox widgets, and their descendants, as typing', () => {
    const { document } = new JSDOM(
      '<body><div role="textbox" id="t"><span id="t-child">x</span></div>' +
        '<div role="combobox" id="c"></div><div role="searchbox" id="s"></div><div id="plain"></div></body>',
    ).window;
    for (const id of ['t', 't-child', 'c', 's']) assert.equal(isTypingTarget(document.getElementById(id)), true, id);
    assert.equal(isTypingTarget(document.getElementById('plain')), false);
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

  it('ignores a held-down key repeat', () => {
    assert.equal(isFocusSearchShortcut(press({ repeat: true })), false);
  });

  it('ignores a slash pressed inside an open modal so focus cannot escape it', () => {
    const { document } = new JSDOM(
      '<body><div role="dialog" aria-modal="true"><button id="in">in</button></div>' +
        '<dialog open><button id="native">native</button></dialog><button id="out">out</button></body>',
    ).window;
    const target = (id: string) => document.getElementById(id);
    assert.equal(isFocusSearchShortcut(press({ target: target('in') })), false);
    assert.equal(isFocusSearchShortcut(press({ target: target('native') })), false);
    assert.equal(isFocusSearchShortcut(press({ target: target('out') })), true);
  });
});

describe('areShortcutsEnabled', () => {
  it('is on by default and off only when the stored value is "off"', () => {
    assert.equal(areShortcutsEnabled({ getItem: () => null }), true);
    assert.equal(areShortcutsEnabled({ getItem: () => 'on' }), true);
    assert.equal(areShortcutsEnabled({ getItem: () => 'off' }), false);
  });

  it('stays on when storage throws', () => {
    const blocked = {
      getItem: () => {
        throw new Error('blocked');
      },
    };
    assert.equal(areShortcutsEnabled(blocked), true);
  });
});
