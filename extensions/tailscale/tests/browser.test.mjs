import test from 'node:test';
import assert from 'node:assert/strict';
import { ExtensionError } from '@vyx/extension-sdk';
import browser from '../src/index.ts';

const open = { kind: 'open', commandId: 'browse', reason: 'launch' };
function peer(overrides = {}) {
  return {
    nodeRef: '00000000-0000-4000-8000-000000000001', name: 'workstation',
    dnsName: 'workstation.example.ts.net', addresses: ['100.64.0.1'],
    online: true, os: 'linux', tags: ['tag:engineering'], sshHostKeysAvailable: true,
    ...overrides,
  };
}
function host(statuses) {
  let calls = 0;
  let state = {};
  return {
    get calls() { return calls; },
    async event(event) {
      const result = await browser.onEvent(event, {
        state,
        tailscale: { async status() {
          const status = statuses[calls++];
          assert.notEqual(status, undefined, 'An unexpected status refresh invalidates opaque references');
          if (status instanceof Error) throw status;
          return status;
        } },
        hosts: { async list() { assert.fail('The browser must not read the vault catalog'); } },
        sessions: { async list() { assert.fail('The browser must not inspect sessions'); } },
      });
      if (result.state !== undefined) state = JSON.parse(JSON.stringify(result.state));
      return result;
    },
  };
}

test('refresh replaces references, fresh details require another click, proposals do not refresh', async () => {
  const old = peer();
  const fresh = peer({ nodeRef: '00000000-0000-4000-8000-000000000002', name: 'replacement', online: false });
  const app = host([{ state: 'running', peers: [old] }, { state: 'running', peers: [fresh] }]);
  const list = await app.event(open);
  assert.equal(list.proposal, undefined);
  const details = await app.event({ kind: 'action', actionId: 'details', itemId: list.view.items[0].id });
  assert.equal(details.view.title, 'replacement');
  assert.equal(details.proposal, undefined);
  assert.equal(details.state.selected.nodeRef, fresh.nodeRef);
  for (const [actionId, mode] of [['connect-keyless', 'tailscale-ssh'], ['connect-standard', 'standard-ssh']]) {
    const proposal = await app.event({ kind: 'action', actionId });
    assert.deepEqual(proposal.proposal, { kind: 'connect-tailnet', nodeRef: fresh.nodeRef, mode });
    assert.deepEqual(proposal.view, details.view);
  }
  assert.equal(app.calls, 2);
  const form = await app.event({ kind: 'action', actionId: 'save' });
  assert.equal(form.proposal, undefined);
  assert.deepEqual(form.view.fields.map(field => field.id), ['mode']);
  const cancel = await app.event({ kind: 'submit', actionId: 'cancel-save', values: { mode: 'standard-ssh' } });
  assert.equal(cancel.proposal, undefined);
  assert.deepEqual(cancel.view, details.view);
  await app.event({ kind: 'action', actionId: 'save' });
  const save = await app.event({ kind: 'submit', actionId: 'review-save', values: { mode: 'standard-ssh' } });
  assert.deepEqual(save.proposal, { kind: 'save-tailnet', nodeRef: fresh.nodeRef, mode: 'standard-ssh' });
  assert.equal(app.calls, 2);
});

test('All and Online are explicit refreshes; reload discards selection without proposing', async () => {
  const peers = [peer(), peer({ nodeRef: 'offline', name: 'sleeping', addresses: ['100.64.0.2'], online: false })];
  const app = host(Array.from({ length: 5 }, () => ({ state: 'running', peers })));
  const all = await app.event(open);
  const online = await app.event({ kind: 'action', actionId: 'online' });
  assert.deepEqual(online.view.items.map(item => item.title), ['workstation']);
  const again = await app.event({ kind: 'action', actionId: 'all' });
  assert.deepEqual(again.view.items.map(item => item.title), ['workstation', 'sleeping']);
  await app.event({ kind: 'action', actionId: 'details', itemId: all.view.items[0].id });
  const reload = await app.event({ ...open, reason: 'reload' });
  assert.equal(reload.proposal, undefined);
  assert.deepEqual(reload.state, { filter: 'all' });
  const stale = await app.event({ kind: 'action', actionId: 'connect-keyless' });
  assert.equal(stale.proposal, undefined);
  assert.ok(stale.view.fields.some(field => field.value === 'STALE_TARGET'));
});

test('a full 4,096-device catalog is searchable without storing references in guest state', async () => {
  const peers = Array.from({ length: 4096 }, (_, index) => peer({
    nodeRef: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    name: `node-${index}`, dnsName: undefined, os: undefined, tags: [],
    addresses: [`100.64.${Math.floor(index / 256)}.${index % 256}`],
  }));
  const app = host([{ state: 'running', peers }]);
  const result = await app.event(open);
  assert.equal(result.view.kind, 'list');
  assert.equal(result.view.searchable, true);
  assert.deepEqual(result.view.items.map(item => item.title), peers.map(item => item.name));
  assert.deepEqual(result.state, { filter: 'all' });
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 1024 * 1024 - 1024);
  assert.ok(result.view.items.every(item => Buffer.byteLength(item.id) < 256));
});

test('large Unicode tag metadata remains searchable while selected state stays bounded', async () => {
  const tags = Array.from({ length: 256 }, (_, index) => `tag:${index}:${'\u{20000}'.repeat(240)}`);
  const device = peer({ tags });
  const app = host([{ state: 'running', peers: [device] }, { state: 'running', peers: [device] }]);
  const list = await app.event(open);
  const metadata = list.view.items[0].metadata;
  assert.ok(metadata.every(field => Buffer.byteLength(field.value) <= 8192));
  assert.ok(tags.every(tag => metadata.some(field => field.value.includes(tag))));
  const details = await app.event({ kind: 'action', actionId: 'details', itemId: list.view.items[0].id });
  assert.ok(Buffer.byteLength(JSON.stringify(details.state)) < 65536);
  assert.ok(details.view.fields.every(field => Buffer.byteLength(field.value) <= 8192));
});

test('missing or ambiguous refreshed addresses cannot retain an actionable selection', async () => {
  for (const peers of [[], [peer(), peer({ nodeRef: 'duplicate' })]]) {
    const app = host([{ state: 'running', peers: [peer()] }, { state: 'running', peers }]);
    const list = await app.event(open);
    const result = await app.event({ kind: 'action', actionId: 'details', itemId: list.view.items[0].id });
    assert.equal(result.proposal, undefined);
    assert.equal(result.state.selected, undefined);
    assert.ok(result.view.fields.some(field => field.value === 'STALE_TARGET'));
  }
});

test('permission denial and backend failures remain actionable without proposals', async () => {
  for (const status of [new ExtensionError('PERMISSION_DENIED', 'Not approved'), ...['stopped', 'signed-out', 'needs-approval', 'unavailable'].map(state => ({ state, peers: [] }))]) {
    const app = host([status, { state: 'running', peers: [peer()] }]);
    const failure = await app.event(open);
    assert.equal(failure.view.kind, 'detail');
    assert.equal(failure.proposal, undefined);
    assert.deepEqual(failure.view.actions.map(action => action.id), ['refresh']);
    const recovered = await app.event({ kind: 'action', actionId: 'refresh' });
    assert.equal(recovered.view.items[0].title, 'workstation');
    assert.equal(recovered.proposal, undefined);
  }
});

test('an invalid save mode never creates a fallback authentication proposal', async () => {
  const app = host([{ state: 'running', peers: [peer()] }, { state: 'running', peers: [peer()] }]);
  const list = await app.event(open);
  await app.event({ kind: 'action', actionId: 'details', itemId: list.view.items[0].id });
  await app.event({ kind: 'action', actionId: 'save' });
  const result = await app.event({ kind: 'submit', actionId: 'review-save', values: { mode: 'agent' } });
  assert.equal(result.proposal, undefined);
  assert.equal(result.state.selected, undefined);
  assert.ok(result.view.fields.some(field => field.value === 'INVALID_ARGUMENT'));
});
