import '@/test/dom-setup';
import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';
import { cleanup, fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import { PwaInstall } from '@/components/pwa-install';
afterEach(() => cleanup());
it('does not offer installation without a native browser prompt', () => {
  render(<PwaInstall />);
  assert.equal(screen.queryByRole('button', {name: /Install Netsight/}), null);
});
it('registers securely, installs only on a user gesture and clears the prompt', async () => {
  Object.defineProperty(window, 'isSecureContext', {configurable:true,value:true});
  const registrations: unknown[] = [];
  Object.defineProperty(navigator, 'serviceWorker', {configurable:true,value:{register: async (...args: unknown[]) => {registrations.push(args); return {};}}});
  render(<PwaInstall />);
  await waitFor(() => assert.equal(registrations.length, 1));
  assert.deepEqual(registrations[0], ['/sw.js', {scope:'/',updateViaCache:'none'}]);
  let prompts = 0;
  const event = new window.Event('beforeinstallprompt', {cancelable:true});
  Object.assign(event, {prompt: async () => {prompts++;}, userChoice: Promise.resolve({outcome:'accepted'})});
  act(() => {window.dispatchEvent(event);});
  assert.equal(prompts, 0);
  fireEvent.click(screen.getByRole('button', {name: /Install Netsight/}));
  await waitFor(() => assert.equal(prompts, 1));
  assert.equal(screen.queryByRole('button', {name: /Install Netsight/}), null);
});
