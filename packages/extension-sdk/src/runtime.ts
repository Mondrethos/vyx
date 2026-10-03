import { ExtensionError, type ErrorCode, type ExtensionDefinition, type ExtensionEvent, type HostMetadata, type Json, type SessionMetadata, type TailscaleStatus } from './index.js';
import { check, controls, encoder, jsonBytes, object, parseJson } from './validation.js';
import { validateResult } from './validation.js';

/** Private runtime seam used by the entry adapter and deterministic consumer tests. */
export interface GuestIO {
  readSync(fd: number, bytes: Uint8Array): number | null;
  writeSync(fd: number, bytes: Uint8Array): number;
}
declare const Javy: { IO: GuestIO };
export function guestIO(): GuestIO { return Javy.IO; }
function writeAll(io: GuestIO, fd: number, bytes: Uint8Array): void {
  let offset = 0;
  while (offset < bytes.length) {
    const count = io.writeSync(fd, bytes.subarray(offset));
    check(Number.isInteger(count) && count > 0 && count <= bytes.length - offset, 'Failed writing guest stream');
    offset += count;
  }
}
function readExact(io: GuestIO, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const count = io.readSync(0, bytes.subarray(offset));
    check(count !== null && Number.isInteger(count) && count > 0 && count <= length - offset, 'Truncated broker frame');
    offset += count;
  }
  return bytes;
}
function readFrame(io: GuestIO): Record<string, unknown> {
  const header = readExact(io, 4);
  const length = new DataView(header.buffer).getUint32(0, true);
  check(length > 0 && length <= 1024 * 1024, 'Invalid broker frame size', 'LIMIT_EXCEEDED');
  const bytes = readExact(io, length);
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return object(parseJson(source));
}
function writeFrame(io: GuestIO, value: unknown): void {
  const bytes = jsonBytes(value);
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, bytes.length, true);
  writeAll(io, 1, header); writeAll(io, 1, bytes);
}
/** Installed in a dependency evaluated before the author's module, not onEvent. */
export function installConsole(io: GuestIO): (error: unknown) => void {
  let remaining = 65536;
  function diagnostic(...values: unknown[]): void {
    if (remaining === 0) return;
    const parts = values.map(value => {
      try {
        if (value instanceof Error) return `${value instanceof ExtensionError ? `[${value.code}] ` : ''}${value.stack ?? `${value.name}: ${value.message}`}`;
        return typeof value === 'string' ? value : JSON.stringify(value) ?? String(value);
      } catch { return '[unserializable diagnostic]'; }
    });
    const message = parts.join(' ').replace(new RegExp(controls.source, 'gu'), '') + '\n';
    const bytes = encoder.encode(message);
    let end = Math.min(bytes.length, remaining);
    // Never leave a partial UTF-8 codepoint in stderr's bounded diagnostic ring.
    if (end < bytes.length) while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
    try { writeAll(io, 2, bytes.subarray(0, end)); } catch { remaining = 0; return; }
    remaining -= end;
    if (end < bytes.length) remaining = 0;
  }
  globalThis.console = { ...globalThis.console, log: diagnostic, info: diagnostic, warn: diagnostic, error: diagnostic, debug: diagnostic };
  return diagnostic;
}
const errorCodes: Record<ErrorCode, true> = {
  PERMISSION_DENIED: true, STALE_TARGET: true, INVALID_ARGUMENT: true, UNAVAILABLE: true,
  LIMIT_EXCEEDED: true, CANCELLED: true, RUNTIME_FAILED: true,
};
/** Exactly one event and tentative final result per fresh Wasm instance. */
export async function run(definition: ExtensionDefinition, io: GuestIO): Promise<void> {
  const input = readFrame(io);
  check(input.kind === 'event' && typeof input.id === 'number' && Number.isSafeInteger(input.id) && input.id > 0, 'Invalid event envelope');
  const eventId = input.id;
  check(Number.isSafeInteger((eventId - 1) * 32 + 32), 'Event ID exceeds safe request range', 'LIMIT_EXCEEDED');
  jsonBytes(input.state, 65536);
  const event = object(input.event);
  check(event.kind === 'open' || event.kind === 'action' || event.kind === 'submit', 'Invalid event kind');
  let ordinal = 0;
  let closed = false;
  let queue: Promise<void> = Promise.resolve();
  function request<T>(method: 'hosts.list' | 'sessions.list' | 'tailscale.status'): Promise<T> {
    if (closed) return Promise.reject(new ExtensionError('CANCELLED', 'Event has completed'));
    const operation = queue.then(() => {
      check(++ordinal <= 32, 'Broker call limit exceeded', 'LIMIT_EXCEEDED');
      const id = (eventId - 1) * 32 + ordinal;
      writeFrame(io, { kind: 'request', eventId, id, method });
      const response = readFrame(io);
      check(response.kind === 'response' && response.eventId === eventId && response.id === id, 'Mismatched broker response');
      check(Object.hasOwn(response, 'value') !== Object.hasOwn(response, 'error'), 'Invalid broker response');
      if ('error' in response) {
        const error = object(response.error);
        check(typeof error.code === 'string' && Object.hasOwn(errorCodes, error.code) && typeof error.message === 'string', 'Invalid broker error');
        throw new ExtensionError(error.code as ErrorCode, error.message);
      }
      // The host validates these nonsecret DTOs before serialization.
      return response.value as T;
    });
    queue = operation.then(() => undefined, () => undefined);
    return operation;
  }
  try {
    const result = await definition.onEvent(event as unknown as ExtensionEvent, {
      state: input.state as Json,
      hosts: { list: () => request<HostMetadata[]>('hosts.list') },
      sessions: { list: () => request<SessionMetadata[]>('sessions.list') },
      tailscale: { status: () => request<TailscaleStatus>('tailscale.status') },
    });
    closed = true;
    await queue;
    validateResult(result);
    writeFrame(io, { kind: 'result', eventId, result });
  } finally { closed = true; }
}
