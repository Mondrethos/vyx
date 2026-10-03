import test from 'node:test';
import assert from 'node:assert/strict';
import { defineExtension, ExtensionError, ui } from '../dist/index.js';
import { installConsole, run } from '../dist/runtime.js';
import { validateResult, parseJson } from '../dist/validation.js';

function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
  return Buffer.concat([header, body]);
}
function transport(messages) {
  const input = Buffer.concat(messages.map(frame)); let offset = 0;
  const output = []; const diagnostics = [];
  return {
    io: {
      readSync(_fd, bytes) { const count = Math.min(bytes.length, 7, input.length - offset); bytes.set(input.subarray(offset, offset + count)); offset += count; return count; },
      writeSync(fd, bytes) { const count = Math.min(bytes.length, 11); (fd === 2 ? diagnostics : output).push(Buffer.from(bytes.subarray(0, count))); return count; },
    },
    messages() {
      const bytes = Buffer.concat(output); const values = [];
      for (let start = 0; start < bytes.length;) { const size = bytes.readUInt32LE(start); values.push(JSON.parse(bytes.subarray(start + 4, start + 4 + size))); start += 4 + size; }
      return values;
    },
    diagnostics() { return Buffer.concat(diagnostics); },
  };
}
const open = (state = {}) => ({ kind: 'event', id: 2, event: { kind: 'open', commandId: 'browse', reason: 'launch' }, state });

test('async consumer recovers denied capability and commits its transformed previous state', async () => {
  const channel = transport([open({ visits: 4 }), { kind: 'response', eventId: 2, id: 33, error: { code: 'PERMISSION_DENIED', message: 'Not approved' } }]);
  await run(defineExtension({ async onEvent(_event, ctx) {
    await Promise.resolve();
    try { await ctx.hosts.list(); assert.fail('Missing permission must reject'); }
    catch (error) { assert.ok(error instanceof ExtensionError); assert.equal(error.code, 'PERMISSION_DENIED'); }
    return { view: ui.detail({ title: 'Permission required', fields: [{ label: 'Visits', value: String(ctx.state.visits + 1) }] }), state: { visits: ctx.state.visits + 1 } };
  } }), channel.io);
  assert.deepEqual(channel.messages().at(-1), { kind: 'result', eventId: 2, result: { view: { kind: 'detail', title: 'Permission required', fields: [{ label: 'Visits', value: '5' }] }, state: { visits: 5 } } });
});

test('concurrent consumer calls serialize and stale responses cannot publish a result', async () => {
  const channel = transport([open(), { kind: 'response', eventId: 1, id: 33, value: [] }]);
  await assert.rejects(run(defineExtension({ async onEvent(_event, ctx) {
    await Promise.all([ctx.hosts.list(), ctx.sessions.list()]);
    return { view: ui.list({ title: 'Should not appear', items: [] }) };
  } }), channel.io), /Mismatched broker response/);
  assert.equal(channel.messages().some(message => message.kind === 'result'), false);
});

test('async consumer error cannot publish tentative state or proposal', async () => {
  const channel = transport([open()]);
  await assert.rejects(run(defineExtension({ async onEvent() { await Promise.resolve(); throw new Error('Consumer failure'); } }), channel.io), /Consumer failure/);
  assert.deepEqual(channel.messages(), []);
});

test('unrenderable actions and credential-like field kinds are rejected before publication', () => {
  assert.throws(() => validateResult({ view: ui.list({ title: 'Devices', items: [{ id: 'peer', title: 'Peer', actions: ['connect'] }], actions: [] }) }), /action reference/);
  assert.throws(() => validateResult({ view: ui.list({ title: 'Devices', items: [{ id: 'peer', title: 'One' }, { id: 'peer', title: 'Two' }] }) }), /Duplicate item/);
  assert.throws(() => validateResult({ view: { kind: 'form', title: 'Unsafe', fields: [{ kind: 'password', id: 'secret', label: 'Password' }] } }), /field kind/);
  assert.throws(() => validateResult({ view: ui.form({ title: 'Choose', fields: [{ kind: 'select', id: 'scope', label: 'Scope', options: [{ id: 'one', label: 'One' }], value: 'absent' }] }) }), /not an option/);
});

test('terminal proposal rejects hidden execution separators without rewriting them', () => {
  const view = ui.detail({ title: 'Review', fields: [] });
  for (const command of ['pwd\nwhoami', 'pwd\r', 'pwd\u2028whoami', 'pwd\u001b[0m', 'pwd\u202e']) {
    assert.throws(() => validateResult({ view, proposal: { kind: 'insert-command', sessionId: '11111111-1111-1111-1111-111111111111', command } }), /controls or line separators/);
  }
});

test('nested duplicate JSON keys and oversized state are consumer errors', () => {
  assert.throws(() => parseJson('{"view":{"title":"one","title":"two"}}'), /Duplicate JSON key/);
  assert.throws(() => parseJson('['.repeat(33) + '0' + ']'.repeat(33)), /depth limit/);
  assert.throws(() => validateResult({ view: ui.detail({ title: 'View', fields: [] }), state: 'x'.repeat(65536) }), error => error.code === 'LIMIT_EXCEEDED');
});

test('diagnostics cannot emit terminal controls or overflow the event budget', () => {
  const original = globalThis.console;
  const channel = transport([]);
  try {
    const diagnostic = installConsole(channel.io);
    console.log('\u001b]52;c;secret\u0007\u202e');
    diagnostic('😀'.repeat(40000)); diagnostic('discarded');
  } finally { globalThis.console = original; }
  const bytes = channel.diagnostics();
  assert.ok(bytes.length <= 65536);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assert.doesNotMatch(text, /[\u001b\u0007\u202e]/u);
  assert.equal(text.includes('discarded'), false);
  assert.deepEqual(channel.messages(), []);
});
