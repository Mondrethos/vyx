/** API v1. All values are nonsecret; operations remain subject to current host grants. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Permission = 'hosts.read' | 'sessions.read' | 'tailscale.read' | 'terminal.propose' | 'connections.propose' | 'hosts.propose';
export type ErrorCode = 'PERMISSION_DENIED' | 'STALE_TARGET' | 'INVALID_ARGUMENT' | 'UNAVAILABLE' | 'LIMIT_EXCEEDED' | 'CANCELLED' | 'RUNTIME_FAILED';
/** Broker failures can be caught without inspecting human-readable wording. */
export class ExtensionError extends Error {
  constructor(public readonly code: ErrorCode, message: string) { super(message); this.name = 'ExtensionError'; }
}
export type ExtensionEvent =
  | { kind: 'open'; commandId: string; reason: 'launch' | 'reload' }
  | { kind: 'action'; actionId: string; itemId?: string }
  | { kind: 'submit'; actionId: string; values: Record<string, string | boolean> };
export interface Action { id: string; label: string }
export interface DetailField { label: string; value: string }
export interface ListItem { id: string; title: string; subtitle?: string; metadata?: DetailField[]; actions?: string[] }
export interface SelectOption { id: string; label: string }
/** Never collect credentials in extension forms: all entered values reach the extension. */
export type FormField =
  | { kind: 'text'; id: string; label: string; value?: string; maxLength: number }
  | { kind: 'select'; id: string; label: string; options: SelectOption[]; value?: string }
  | { kind: 'toggle'; id: string; label: string; value?: boolean };
export interface ListView { kind: 'list'; title: string; searchable?: boolean; items: ListItem[]; actions?: Action[] }
export interface DetailView { kind: 'detail'; title: string; fields: DetailField[]; actions?: Action[] }
export interface FormView { kind: 'form'; title: string; fields: FormField[]; actions?: Action[] }
export type View = ListView | DetailView | FormView;
/** Constructors describe host-rendered plain text; they never perform host actions. */
export const ui = {
  list: (view: Omit<ListView, 'kind'>): ListView => ({ ...view, kind: 'list' }),
  detail: (view: Omit<DetailView, 'kind'>): DetailView => ({ ...view, kind: 'detail' }),
  form: (view: Omit<FormView, 'kind'>): FormView => ({ ...view, kind: 'form' }),
};
export type ConnectionMode = 'tailscale-ssh' | 'standard-ssh';
/** A proposal only requests host-owned review. It cannot execute, insert, connect or save. */
export type Proposal =
  | { kind: 'insert-command'; sessionId: string; command: string }
  | { kind: 'connect-saved'; hostId: string }
  | { kind: 'connect-tailnet'; nodeRef: string; mode: ConnectionMode }
  | { kind: 'save-tailnet'; nodeRef: string; mode: ConnectionMode };
export interface HostMetadata { id: string; label: string; address: string; port: number; category?: string; authenticationMode: string }
export type SessionPhase = 'connecting' | 'authenticating' | 'connected' | 'disconnected' | 'failed';
export interface SessionMetadata { id: string; label: string; hostId?: string; phase: SessionPhase }
export type TailscaleState = 'running' | 'stopped' | 'signed-out' | 'needs-approval' | 'unavailable';
export interface TailscalePeer {
  nodeRef: string; name?: string; dnsName?: string; addresses: string[]; online: boolean;
  lastSeen?: string; os?: string; tags: string[]; sshHostKeysAvailable: boolean;
}
export interface TailscaleStatus { state: TailscaleState; tailnetName?: string; peers: TailscalePeer[] }
export interface ExtensionContext {
  /** Previous successful JSON state. Initially {}; omitted result state preserves it.
   * Close, reload, failure, lock and detach discard it. Globals are not persistent. */
  readonly state: Json;
  readonly hosts: { list(): Promise<HostMetadata[]> };
  readonly sessions: { list(): Promise<SessionMetadata[]> };
  readonly tailscale: { status(): Promise<TailscaleStatus> };
}
export interface ExtensionResult { view: View; state?: Json; proposal?: Proposal }
export interface ExtensionDefinition {
  onEvent(event: ExtensionEvent, ctx: ExtensionContext): ExtensionResult | Promise<ExtensionResult>;
}
/** Default-export the returned definition. Each event runs in a fresh isolated instance.
 * Async broker calls work; timers, fetch, Node, DOM and ambient I/O are not provided. */
export function defineExtension(definition: ExtensionDefinition): ExtensionDefinition { return definition; }
export type { Manifest, ManifestCommand } from './manifest.js';
