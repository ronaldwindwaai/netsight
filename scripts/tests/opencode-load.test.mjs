import assert from 'node:assert/strict';
import test from 'node:test';
import plugin from '../../.opencode/dist/index.js';

test('OpenCode V2 registers ECC hooks and preserves unknown-action decisions', async () => {
  const hooks = new Map();
  const tools = [];
  const domain = (name) => ({
    async hook(event, handler) { hooks.set(`${name}.${event}`, handler); },
  });
  assert.equal(plugin.id, 'ecc');
  const dispose = await plugin.setup({
    location: { directory: process.cwd() },
    tool: { ...domain('tool'), transform(callback) { callback({ add(tool) { tools.push(tool); } }); } },
    shell: domain('shell'), permission: domain('permission'), session: domain('session'),
    event: { async *subscribe() {} },
  });
  try {
    assert.equal(typeof dispose, 'function');
    assert.equal(tools.length, 2);
    for (const name of ['tool.execute.before', 'tool.execute.after', 'shell.create.before',
      'permission.evaluate', 'session.compaction']) assert.ok(hooks.has(name), name);
    const evaluate = hooks.get('permission.evaluate');
    const read = { action: 'read', effect: 'ask' };
    evaluate(read);
    assert.equal(read.effect, 'allow');
    const write = { action: 'write', effect: 'deny' };
    evaluate(write);
    assert.equal(write.effect, 'deny');
    const shell = { action: 'bash', effect: 'ask', metadata: { command: 'curl https://example.com' } };
    evaluate(shell);
    assert.equal(shell.effect, 'ask');
  } finally { dispose(); }
});
