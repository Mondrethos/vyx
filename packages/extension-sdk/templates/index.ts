import { defineExtension, ui, type Json, type View } from '@vyx/extension-sdk';

export default defineExtension({
  async onEvent(event, ctx) {
    const state = ctx.state !== null && typeof ctx.state === 'object' && !Array.isArray(ctx.state) ? ctx.state : {};
    const visits = typeof state.visits === 'number' ? state.visits : 0;
    const note = typeof state.note === 'string' ? state.note : '';
    const target = typeof state.target === 'string' ? state.target : '';
    const next: { [key: string]: Json } = { visits: visits + 1, note, target };
    if (event.kind === 'action' && event.actionId === 'preferences') {
      return { state: next, view: ui.form({
        title: 'Example preferences — never enter credentials',
        fields: [
          { kind: 'text', id: 'note', label: 'Display note', value: note, maxLength: 256 },
          { kind: 'select', id: 'scope', label: 'Scope', options: [{ id: 'local', label: 'This open surface' }], value: 'local' },
          { kind: 'toggle', id: 'show', label: 'Show note', value: true },
        ],
        actions: [{ id: 'save-preferences', label: 'Apply' }],
      }) };
    }
    if (event.kind === 'submit' && event.actionId === 'save-preferences') {
      next.note = event.values.show === true && typeof event.values.note === 'string' ? event.values.note : '';
    }
    // Broker operations are asynchronous and independently permission checked.
    const [hosts, sessions] = await Promise.all([ctx.hosts.list(), ctx.sessions.list()]);
    const selected = event.kind === 'action' ? event.itemId ?? target : target;
    const host = hosts.find(item => `host:${item.id}` === selected);
    const session = sessions.find(item => `session:${item.id}` === selected);
    const list: View = ui.list({
      title: `Saved hosts and sessions (${next.visits} events)`, searchable: true,
      items: [
        ...hosts.map(item => ({ id: `host:${item.id}`, title: item.label, subtitle: `${item.address}:${item.port}`, actions: ['details'] })),
        ...sessions.map(item => ({ id: `session:${item.id}`, title: item.label, subtitle: item.phase, actions: ['details'] })),
      ],
      actions: [{ id: 'details', label: 'Details' }, { id: 'refresh', label: 'Refresh' }, { id: 'preferences', label: 'Preferences' }],
    });
    if (event.kind === 'action' && event.actionId === 'details' && (host || session)) {
      next.target = selected;
      return { state: next, view: ui.detail({
        title: host?.label ?? session!.label,
        fields: [
          { label: 'Destination / phase', value: host ? `${host.address}:${host.port}` : session!.phase },
          { label: 'Note', value: String(next.note) },
          { label: 'Approval', value: 'The following action opens a Vyx-owned review. Nothing executes automatically.' },
        ],
        actions: [{ id: host ? 'connect' : 'insert', label: host ? 'Propose connection' : 'Propose pwd insertion' }, { id: 'refresh', label: 'Back' }],
      }) };
    }
    // Only explicit actions propose; reload/open never proposes or reuses intent.
    if (event.kind === 'action' && event.actionId === 'connect' && host) {
      return { view: list, state: next, proposal: { kind: 'connect-saved', hostId: host.id } };
    }
    if (event.kind === 'action' && event.actionId === 'insert' && session?.phase === 'connected') {
      return { view: list, state: next, proposal: { kind: 'insert-command', sessionId: session.id, command: 'pwd' } };
    }
    return { view: list, state: next };
  },
});
