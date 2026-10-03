import {
  defineExtension, ExtensionError, ui,
  type Action, type DetailField, type ExtensionContext, type ExtensionEvent,
  type ExtensionResult, type Json, type TailscalePeer, type TailscaleStatus,
} from '@vyx/extension-sdk';

// Provided by Javy's explicitly enabled text-encoding capability, not the DOM.
declare const TextEncoder: { new(): { encode(input: string): Uint8Array } };
const encoder = new TextEncoder();

const refresh: Action = { id: 'refresh', label: 'Refresh devices' };
const policy = 'Online status and advertised SSH host keys do not prove SSH policy authorization. Vyx never changes Tailscale policy or enables SSH.';
const standard = 'Standard SSH uses the machine’s ordinary SSH service and your Vyx-owned credentials/password. On port 22, an enabled Tailscale SSH server may intercept it. Modes never fall back to one another.';
const keyless = 'Tailscale SSH uses port 22, your remote username, and Tailscale-distributed host keys, without a saved credential. Check mode may require opening a server-provided HTTPS link manually.';
const detailActions: Action[] = [
  { id: 'connect-keyless', label: 'Connect with Tailscale SSH' },
  { id: 'connect-standard', label: 'Connect with standard SSH' },
  { id: 'save', label: 'Save server…' },
  refresh,
];

type Filter = 'all' | 'online';
interface Selection { nodeRef: string; title: string; fields: DetailField[] }
interface State { filter: Filter; selected?: Selection }

function record(value: Json): { [key: string]: Json } {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
function readState(value: Json): State {
  const stored = record(value);
  const state: State = { filter: stored.filter === 'online' ? 'online' : 'all' };
  const selected = record(stored.selected ?? null);
  if (typeof selected.nodeRef === 'string' && typeof selected.title === 'string' && Array.isArray(selected.fields)) {
    const fields: DetailField[] = [];
    for (const entry of selected.fields) {
      const field = record(entry);
      if (typeof field.label !== 'string' || typeof field.value !== 'string') return state;
      fields.push({ label: field.label, value: field.value });
    }
    state.selected = { nodeRef: selected.nodeRef, title: selected.title, fields };
  }
  return state;
}
function stored(state: State): Json {
  // Never retain the peer catalog: even 4,096 opaque references exceed 64 KiB.
  if (!state.selected) return { filter: state.filter };
  return { filter: state.filter, selected: {
    nodeRef: state.selected.nodeRef, title: state.selected.title,
    fields: state.selected.fields.map(field => ({ label: field.label, value: field.value })),
  } };
}
function limit(value: string, characters: number): string {
  const text = [...value];
  return text.length <= characters ? value : `${text.slice(0, characters - 1).join('')}…`;
}
function itemId(peer: TailscalePeer): string {
  const address = peer.addresses[0];
  if (!address) throw new ExtensionError('UNAVAILABLE', 'A device has no usable Tailscale address. Refresh after checking the local Tailscale installation.');
  const id = `${peer.nodeRef}|${address}`;
  if (encoder.encode(id).length > 256) throw new ExtensionError('LIMIT_EXCEEDED', 'A device reference exceeds the browser item limit.');
  return id;
}
function metadata(peer: TailscalePeer): DetailField[] {
  // All metadata remains in the host-rendered list, so local search includes every
  // IP, DNS name and tag. Do not truncate search results to fit guest state.
  const parts = [
    peer.online ? 'Online' : 'Offline',
    ...peer.addresses,
    ...(peer.dnsName ? [peer.dnsName] : []),
    ...(peer.os ? [peer.os] : []),
    ...(peer.lastSeen ? [`Last seen: ${peer.lastSeen}`] : []),
    `SSH keys: ${peer.sshHostKeysAvailable ? 'advertised' : 'not advertised'}`,
    ...peer.tags,
  ];
  const fields: DetailField[] = [];
  let value = '';
  let characters = 0;
  // At most 2,048 Unicode scalars per value: at most 8 KiB UTF-8.
  // Keep each tag/address intact: host search operates on individual fields.
  for (const part of parts) {
    const length = [...part].length;
    if (characters + length + 3 > 2048 && value) {
      fields.push({ label: 'Device', value });
      value = '';
      characters = 0;
    }
    if (value) { value += ' · '; characters += 3; }
    value += part;
    characters += length;
  }
  if (value) fields.push({ label: 'Device', value });
  return fields;
}
function selection(peer: TailscalePeer, address: string): Selection {
  const fields: DetailField[] = [
    { label: 'Snapshot', value: `Fresh metadata, matched by the selected exact IP ${address}. Confirm this device below; an address may have changed owners since the list was loaded. Actions now use this refreshed device reference.` },
    { label: 'Tailscale IPs', value: peer.addresses.join(', ') },
    { label: 'Status', value: peer.online ? 'Online' : 'Offline — connection may fail; this is not a policy verdict' },
    { label: 'SSH host keys', value: peer.sshHostKeysAvailable ? 'Advertised — keyless mode verifies the actual server key before authentication' : 'Not advertised — keyless mode cannot connect without valid distributed keys' },
  ];
  if (peer.name) fields.push({ label: 'Name', value: peer.name });
  if (peer.dnsName) fields.push({ label: 'MagicDNS', value: peer.dnsName });
  if (peer.os) fields.push({ label: 'OS', value: peer.os });
  if (peer.lastSeen) fields.push({ label: 'Last seen', value: peer.lastSeen });
  if (peer.tags.length) {
    const tags = peer.tags.join(', ');
    fields.push({ label: 'Tags (summary; full tags searchable in device list)', value: limit(tags, 1800) });
  }
  fields.push(
    { label: 'Authorization', value: policy },
    { label: 'Tailscale SSH', value: keyless },
    { label: 'Standard SSH', value: standard },
    { label: 'Review', value: 'Connect once does not save a server. Save only opens a Vyx-owned draft; saving is separate from connecting. Vyx collects all usernames, credentials, ports and categories outside this extension.' },
  );
  return { nodeRef: peer.nodeRef, title: limit(peer.name || peer.dnsName || peer.addresses[0] || 'Unnamed device', 256), fields };
}
function selected(state: State): Selection {
  if (!state.selected) throw new ExtensionError('STALE_TARGET', 'Select a device and open its fresh details before choosing an action.');
  return state.selected;
}
function detail(state: State): ExtensionResult {
  const peer = selected(state);
  return { state: stored(state), view: ui.detail({ title: peer.title, fields: peer.fields, actions: detailActions }) };
}
function unavailable(state: State, title: string, message: string, code?: string): ExtensionResult {
  return {
    state: { filter: state.filter },
    view: ui.detail({ title, fields: [
      ...(code ? [{ label: 'Code', value: code }] : []),
      { label: 'Next step', value: limit(message, 1800) },
      { label: 'Local setup', value: 'Install/sign in to Tailscale outside Vyx. Check its daemon and machine approval, and the CLI path in Vyx Settings. Vyx never runs login, enables SSH, or changes policy. Then choose Refresh.' },
    ], actions: [refresh] }),
  };
}
function backend(status: TailscaleStatus, state: State): ExtensionResult | undefined {
  switch (status.state) {
    case 'running': return undefined;
    case 'stopped': return unavailable(state, 'Tailscale is stopped', 'Start Tailscale using its own controls, then Refresh.');
    case 'signed-out': return unavailable(state, 'Tailscale is signed out', 'Sign in using Tailscale outside Vyx, then Refresh.');
    case 'needs-approval': return unavailable(state, 'Machine approval required', 'Ask your tailnet administrator to approve this machine, then Refresh.');
    case 'unavailable': return unavailable(state, 'Tailscale unavailable', 'Check the installed CLI path and that the local daemon is reachable, then Refresh.');
  }
}
async function browse(ctx: ExtensionContext, state: State): Promise<ExtensionResult> {
  const status = await ctx.tailscale.status();
  const failure = backend(status, state);
  if (failure) return failure;
  const peers = state.filter === 'online' ? status.peers.filter(peer => peer.online) : status.peers;
  if (!peers.length) return {
    state: { filter: state.filter },
    view: ui.detail({ title: state.filter === 'online' ? 'No online devices' : 'No visible Tailscale devices', fields: [
      { label: 'Next step', value: 'Check device visibility in Tailscale outside Vyx. Choose All devices to include offline peers, or Refresh after changes.' },
      { label: 'Authorization', value: policy },
    ], actions: [refresh, { id: 'all', label: 'All devices (refresh)' }] }),
  };
  return {
    state: { filter: state.filter },
    view: ui.list({
      title: limit(`Tailscale · ${state.filter === 'online' ? 'Online' : 'All'} · ${peers.length}${status.tailnetName ? ` · ${status.tailnetName}` : ''}`, 256),
      searchable: true,
      items: peers.map(peer => ({
        id: itemId(peer), title: limit(peer.name || peer.dnsName || peer.addresses[0] || 'Unnamed device', 256),
        metadata: metadata(peer), actions: ['details'],
      })),
      actions: [
        { id: 'details', label: 'Fresh device details / actions' }, refresh,
        { id: 'all', label: 'All devices (refresh)' },
        { id: 'online', label: 'Online devices (refresh)' },
        { id: 'about', label: 'About SSH modes / policy' },
      ],
    }),
  };
}
async function handle(event: ExtensionEvent, ctx: ExtensionContext, state: State): Promise<ExtensionResult> {
  if (event.kind === 'open') {
    if (event.commandId !== 'browse') throw new ExtensionError('INVALID_ARGUMENT', 'Unknown browser command.');
    // Launch and reload both discard prior selection, and can never propose.
    return browse(ctx, { filter: 'all' });
  }
  if (event.kind === 'action') {
    switch (event.actionId) {
      case 'refresh': return browse(ctx, state);
      case 'all': return browse(ctx, { filter: 'all' });
      case 'online': return browse(ctx, { filter: 'online' });
      case 'about': return { state: { filter: state.filter }, view: ui.detail({ title: 'Tailscale connection modes', fields: [
        { label: 'Authorization', value: policy }, { label: 'Tailscale SSH', value: keyless }, { label: 'Standard SSH', value: standard },
      ], actions: [refresh] }) };
      case 'details': {
        // The old opaque reference is carried in the item ID, not kept in a
        // 4,096-entry guest-state map. Only this explicit action refreshes it.
        const boundary = event.itemId?.lastIndexOf('|') ?? -1;
        if (!event.itemId || boundary <= 0) throw new ExtensionError('STALE_TARGET', 'Choose a device from a freshly loaded list.');
        const address = event.itemId.slice(boundary + 1);
        const status = await ctx.tailscale.status();
        const failure = backend(status, state);
        if (failure) return failure;
        const matches = status.peers.filter(peer => peer.addresses.includes(address));
        const peer = matches[0];
        if (matches.length !== 1 || !peer) throw new ExtensionError('STALE_TARGET', 'The selected IP is missing or ambiguous. Refresh and select the intended device again.');
        return detail({ filter: state.filter, selected: selection(peer, address) });
      }
      case 'connect-keyless':
      case 'connect-standard': {
        const peer = selected(state);
        return { ...detail(state), proposal: {
          kind: 'connect-tailnet', nodeRef: peer.nodeRef,
          mode: event.actionId === 'connect-keyless' ? 'tailscale-ssh' : 'standard-ssh',
        } };
      }
      case 'save': {
        const peer = selected(state);
        return { state: stored(state), view: ui.form({
          title: limit(`Save ${peer.title} — choose authentication mode`, 256),
          fields: [{ kind: 'select', id: 'mode', label: 'Mode (standard SSH on port 22 may be intercepted by Tailscale SSH)',
            options: [
              { id: 'tailscale-ssh', label: 'Tailscale SSH — keyless, port 22' },
              { id: 'standard-ssh', label: 'Standard SSH — ordinary SSH service with Vyx credentials/password' },
            ],
          }],
          actions: [{ id: 'review-save', label: 'Open Vyx server draft' }, { id: 'cancel-save', label: 'Cancel' }],
        }) };
      }
    }
  }
  if (event.kind === 'submit') {
    if (event.actionId === 'cancel-save') return detail(state);
    if (event.actionId === 'review-save') {
      const peer = selected(state);
      const mode = event.values.mode;
      if (mode !== 'tailscale-ssh' && mode !== 'standard-ssh') throw new ExtensionError('INVALID_ARGUMENT', 'Choose an explicit SSH mode.');
      return { ...detail(state), proposal: { kind: 'save-tailnet', nodeRef: peer.nodeRef, mode } };
    }
  }
  throw new ExtensionError('INVALID_ARGUMENT', 'Unknown browser action. Refresh to return to the device list.');
}

export default defineExtension({
  async onEvent(event, ctx) {
    const state = readState(ctx.state);
    try {
      const result = await handle(event, ctx, state);
      // Never silently drop peers or searchable metadata to fit a protocol frame.
      if (encoder.encode(JSON.stringify(result)).length > 1024 * 1024 - 1024) {
        return unavailable(state, 'Device metadata exceeds the view limit', 'The complete searchable result exceeds 1 MiB. No partial device list was shown. Reduce visible peers or metadata using Tailscale administration outside Vyx, then Refresh.', 'LIMIT_EXCEEDED');
      }
      return result;
    } catch (error) {
      if (error instanceof ExtensionError && error.code === 'PERMISSION_DENIED') {
        return unavailable(state, 'Tailscale permission required', 'Review and approve this package’s permissions in Settings / Extensions, reopen the browser, then Refresh. No device action was proposed.', error.code);
      }
      return unavailable(state, 'Unable to browse Tailscale devices', error instanceof Error ? error.message : 'The local Tailscale request failed. Check the installation and Refresh.', error instanceof ExtensionError ? error.code : 'UNAVAILABLE');
    }
  },
});
