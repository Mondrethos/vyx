import { ExtensionError, type ExtensionResult } from './index.js';

export const encoder = new TextEncoder();
export const controls = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
export function check(condition: unknown, message: string, code: 'INVALID_ARGUMENT' | 'LIMIT_EXCEEDED' = 'INVALID_ARGUMENT'): asserts condition {
  if (!condition) throw new ExtensionError(code, message);
}
export function object(value: unknown): Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value), 'Expected an object');
  return value as Record<string, unknown>;
}
export function keys(value: Record<string, unknown>, allowed: string[]): void {
  check(Object.keys(value).every(key => allowed.includes(key)), 'Unknown field');
}
export function text(value: unknown, limit: number, bytes = false): asserts value is string {
  check(typeof value === 'string', 'Expected text');
  check((bytes ? encoder.encode(value).length : [...value].length) <= limit, 'Text size limit exceeded', 'LIMIT_EXCEEDED');
}
export function id(value: unknown): asserts value is string {
  text(value, 256, true);
  check(value.trim() && !controls.test(value) && !/[\u2028\u2029]/u.test(value), 'Invalid ID');
}
function array(value: unknown, limit: number): unknown[] {
  check(Array.isArray(value), 'Expected an array');
  check(value.length <= limit, 'Array size limit exceeded', 'LIMIT_EXCEEDED');
  return value;
}
/** Reject duplicate keys and excessive depth before constructing JSON values. */
export function parseJson(source: string): unknown {
  let pos = 0;
  function space(): void { while (/\s/u.test(source[pos] ?? '') && pos < source.length) pos++; }
  function stringToken(): string {
    const start = pos++;
    while (pos < source.length) {
      const char = source[pos++];
      if (char === '\\') pos++;
      else if (char === '"') return JSON.parse(source.slice(start, pos)) as string;
    }
    throw new ExtensionError('INVALID_ARGUMENT', 'Truncated JSON string');
  }
  function value(depth: number): void {
    space();
    const char = source[pos];
    if (char === '{' || char === '[') {
      check(depth < 32, 'JSON depth limit exceeded', 'LIMIT_EXCEEDED');
      pos++;
      const end = char === '{' ? '}' : ']';
      const seen = new Set<string>();
      space();
      if (source[pos] === end) { pos++; return; }
      while (pos < source.length) {
        if (char === '{') {
          space(); check(source[pos] === '"', 'Expected JSON key');
          const key = stringToken();
          check(!seen.has(key), 'Duplicate JSON key'); seen.add(key);
          space(); check(source[pos++] === ':', 'Expected JSON colon');
        }
        value(depth + 1); space();
        const next = source[pos++];
        if (next === end) return;
        check(next === ',', 'Expected JSON comma');
      }
      check(false, 'Truncated JSON');
    } else if (char === '"') stringToken();
    else {
      const start = pos;
      while (pos < source.length && !/[\s,\]}]/u.test(source[pos]!)) pos++;
      check(pos > start, 'Invalid JSON value');
      JSON.parse(source.slice(start, pos));
    }
  }
  value(0); space(); check(pos === source.length, 'Trailing JSON data');
  return JSON.parse(source) as unknown;
}
export function jsonBytes(value: unknown, limit = 1024 * 1024): Uint8Array {
  const source = JSON.stringify(value, (_key, item: unknown) => {
    check(item !== undefined && typeof item !== 'function' && typeof item !== 'symbol' && typeof item !== 'bigint', 'Value is not JSON');
    if (typeof item === 'number') check(Number.isFinite(item), 'Nonfinite JSON number');
    return item;
  });
  check(typeof source === 'string', 'Value is not JSON');
  const bytes = encoder.encode(source);
  check(bytes.length <= limit, 'JSON size limit exceeded', 'LIMIT_EXCEEDED');
  parseJson(source);
  return bytes;
}
function details(value: unknown): void {
  for (const entry of array(value, 4096)) {
    const field = object(entry); keys(field, ['label', 'value']);
    text(field.label, 256); text(field.value, 8192, true);
  }
}
export function validateResult(value: unknown): asserts value is ExtensionResult {
  const result = object(value); keys(result, ['view', 'state', 'proposal']);
  if ('state' in result) jsonBytes(result.state, 65536);
  const view = object(result.view);
  text(view.title, 256);
  const actions = new Set<string>();
  for (const entry of array(view.actions ?? [], 16)) {
    const action = object(entry); keys(action, ['id', 'label']);
    id(action.id); text(action.label, 256);
    check(!actions.has(action.id), 'Duplicate action ID'); actions.add(action.id);
  }
  const ids = new Set<string>();
  switch (view.kind) {
    case 'list':
      keys(view, ['kind', 'title', 'searchable', 'items', 'actions']);
      check(view.searchable === undefined || typeof view.searchable === 'boolean', 'Invalid searchable flag');
      for (const entry of array(view.items, 4096)) {
        const item = object(entry); keys(item, ['id', 'title', 'subtitle', 'metadata', 'actions']);
        id(item.id); check(!ids.has(item.id), 'Duplicate item ID'); ids.add(item.id);
        text(item.title, 256); if ('subtitle' in item) text(item.subtitle, 256);
        details(item.metadata ?? []);
        const references = new Set<string>();
        for (const action of array(item.actions ?? [], 16)) {
          id(action); check(actions.has(action) && !references.has(action), 'Invalid item action reference'); references.add(action);
        }
      }
      break;
    case 'detail':
      keys(view, ['kind', 'title', 'fields', 'actions']); details(view.fields); break;
    case 'form':
      keys(view, ['kind', 'title', 'fields', 'actions']);
      for (const entry of array(view.fields, 24)) {
        const field = object(entry); id(field.id); text(field.label, 256);
        check(!ids.has(field.id), 'Duplicate field ID'); ids.add(field.id);
        if (field.kind === 'text') {
          keys(field, ['kind', 'id', 'label', 'value', 'maxLength']);
          check(typeof field.maxLength === 'number' && Number.isInteger(field.maxLength) && field.maxLength > 0 && field.maxLength <= 8192, 'Invalid text field bound');
          text(field.value ?? '', field.maxLength, true); check(!controls.test((field.value ?? '') as string), 'Invalid form value');
        } else if (field.kind === 'toggle') {
          keys(field, ['kind', 'id', 'label', 'value']); check(field.value === undefined || typeof field.value === 'boolean', 'Invalid toggle value');
        } else if (field.kind === 'select') {
          keys(field, ['kind', 'id', 'label', 'value', 'options']);
          const options = new Set<string>();
          for (const option of array(field.options, 4096)) {
            const item = object(option); keys(item, ['id', 'label']); id(item.id); text(item.label, 256);
            check(!options.has(item.id), 'Duplicate select option ID'); options.add(item.id);
          }
          check(options.size > 0, 'Empty select options');
          if ('value' in field) { id(field.value); check(options.has(field.value), 'Select value is not an option'); }
        } else check(false, 'Invalid form field kind');
      }
      break;
    default: check(false, 'Invalid view kind');
  }
  if ('proposal' in result) {
    const proposal = object(result.proposal);
    if (proposal.kind === 'insert-command' || proposal.kind === 'connect-saved') {
      const target = proposal.kind === 'insert-command' ? 'sessionId' : 'hostId';
      keys(proposal, proposal.kind === 'insert-command' ? ['kind', target, 'command'] : ['kind', target]);
      const uuid = proposal[target];
      check(typeof uuid === 'string' && /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iu.test(uuid) && uuid !== '00000000-0000-0000-0000-000000000000', 'Invalid target UUID');
      if (proposal.kind === 'insert-command') {
        text(proposal.command, 8192, true);
        check(proposal.command.length > 0 && !controls.test(proposal.command) && !/[\u2028\u2029]/u.test(proposal.command), 'Command contains controls or line separators');
      }
    } else {
      check(proposal.kind === 'connect-tailnet' || proposal.kind === 'save-tailnet', 'Invalid proposal kind');
      keys(proposal, ['kind', 'nodeRef', 'mode']); id(proposal.nodeRef);
      check(proposal.mode === 'tailscale-ssh' || proposal.mode === 'standard-ssh', 'Invalid connection mode');
    }
  }
  jsonBytes(result);
}
