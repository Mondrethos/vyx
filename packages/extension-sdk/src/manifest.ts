import type { Permission } from './index.js';
import { check, controls, jsonBytes, keys, object, text } from './validation.js';

export interface ManifestCommand { id: string; title: string; description: string }
/** Installed packages automatically appear under Settings / Extensions using
 * their name and stable ID. Opening that entry shows host-owned management and
 * permission controls; it does not run onEvent or grant permissions. */
export interface Manifest {
  schemaVersion: 1; apiVersion: 1; id: string; name: string; description: string;
  version: string; permissions: Permission[]; commands: ManifestCommand[];
}
const permissions: Record<Permission, true> = {
  'hosts.read': true, 'sessions.read': true, 'tailscale.read': true,
  'terminal.propose': true, 'connections.propose': true, 'hosts.propose': true,
};
/** Validate the public manifest, including production reserved IDs. Building a
 * com.vyx.* package does not establish trust: only an official Vyx release does. */
export function validateManifest(value: unknown): asserts value is Manifest {
  jsonBytes(value, 65536);
  const manifest = object(value);
  keys(manifest, ['schemaVersion', 'apiVersion', 'id', 'name', 'description', 'version', 'permissions', 'commands']);
  check(manifest.schemaVersion === 1 && manifest.apiVersion === 1, 'Unsupported manifest schema/API version');
  text(manifest.id, 128, true);
  check(manifest.id.includes('.') && manifest.id.split('.').every(part => /^[a-z](?:[a-z0-9-]*[a-z0-9])?$/u.test(part)), 'Invalid extension ID');
  text(manifest.name, 256); text(manifest.description, 8192);
  check(manifest.name.replace(new RegExp(controls.source, 'gu'), '').trim(), 'Blank extension name');
  text(manifest.version, 128, true);
  check(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/u.test(manifest.version), 'Invalid SemVer');
  check(manifest.version.split(/[+-]/u)[0]!.split('.').every(part => BigInt(part) <= 18446744073709551615n), 'SemVer component exceeds u64');
  check(Array.isArray(manifest.permissions), 'Expected permissions');
  const granted = new Set<string>();
  for (const permission of manifest.permissions as unknown[]) {
    check(typeof permission === 'string' && Object.hasOwn(permissions, permission), 'Unknown permission');
    check(!granted.has(permission), 'Duplicate permission'); granted.add(permission);
  }
  check(Array.isArray(manifest.commands) && manifest.commands.length > 0 && manifest.commands.length <= 32, 'Expected 1 to 32 commands');
  const ids = new Set<string>();
  for (const entry of manifest.commands as unknown[]) {
    const command = object(entry); keys(command, ['id', 'title', 'description']);
    text(command.id, 64, true); check(/^[a-z0-9-]+$/u.test(command.id), 'Invalid command ID');
    check(!ids.has(command.id), 'Duplicate command ID'); ids.add(command.id);
    text(command.title, 256); text(command.description, 8192);
    check(command.title.replace(new RegExp(controls.source, 'gu'), '').trim(), 'Blank command title');
  }
}
