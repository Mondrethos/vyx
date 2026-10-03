import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { sandboxImports, encodePackage, publishPackage } from '../dist/tooling.js';
import { validateManifest } from '../dist/manifest.js';

const manifest = {
  schemaVersion: 1, apiVersion: 1, id: 'org.example.browser', name: 'Browser', description: 'Example', version: '1.0.0',
  permissions: ['hosts.read'], commands: [{ id: 'browse', title: 'Browse', description: 'Hosts' }],
};

test('unknown API/permissions and duplicate command identities are rejected', () => {
  for (const value of [
    { ...manifest, apiVersion: 2 }, { ...manifest, permissions: ['vault.read'] },
    { ...manifest, commands: [manifest.commands[0], manifest.commands[0]] },
    { ...manifest, permissions: ['hosts.read', 'hosts.read'] },
    { ...manifest, version: '1.0.0-01' }, { ...manifest, hooks: { install: 'bad' } },
  ]) assert.throws(() => validateManifest(value));
});

test('oversized and non-core Wasm cannot be distributed as a package', () => {
  assert.throws(() => encodePackage(manifest, new Uint8Array(8 * 1024 * 1024 + 1)), /size/);
  assert.throws(() => encodePackage(manifest, Uint8Array.from([0, 97, 115, 109, 13, 0, 1, 0])), /core Wasm/);
});

test('bundling rejects dynamic imports, dynamic require, Node builtins and unresolved modules', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vyx-sdk-imports-'));
  try {
    await writeFile(join(directory, 'dependency.js'), 'export const value = 1;');
    for (const source of [
      "import('./dependency.js').then(console.log)",
      'import(globalThis.moduleName)',
      'require(globalThis.moduleName)',
      "import {readFileSync} from 'node:fs'; console.log(readFileSync('/etc/passwd'))",
      "import missing from './absent.js'; console.log(missing)",
    ]) {
      await writeFile(join(directory, 'index.js'), source);
      await assert.rejects(build({ entryPoints: [join(directory, 'index.js')], bundle: true, write: false, platform: 'neutral', format: 'esm', plugins: [sandboxImports], logLevel: 'silent' }));
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('release discovery tracks the exact published bytes, manifest and custom asset basename across rebuilds', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vyx-sdk-release-'));
  const wasm = Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const output = join(directory, 'custom-browser.package');
  try {
    for (const current of [manifest, { ...manifest, version: '2.0.0', permissions: ['sessions.read'] }]) {
      await publishPackage(output, current, wasm);
      const bytes = await readFile(output);
      const index = JSON.parse(await readFile(join(directory, 'vyx-extensions.json'), 'utf8'));
      assert.deepEqual(index, {
        schemaVersion: 1,
        extensions: [{
          manifest: current, asset: 'custom-browser.package',
          sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length,
        }],
      });
      assert.equal(bytes.subarray(0, 8).toString(), 'VYXEXT1\n');
      const manifestBytes = bytes.readUInt32LE(8);
      assert.deepEqual(JSON.parse(bytes.subarray(16, 16 + manifestBytes).toString()), current);
      assert.deepEqual(bytes.subarray(16 + manifestBytes), Buffer.from(wasm));
    }
    assert.deepEqual((await readdir(directory)).sort(), ['custom-browser.package', 'vyx-extensions.json']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('invalid output assets and invalid rebuilds cannot replace an existing release pair', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vyx-sdk-release-invalid-'));
  const wasm = Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const output = join(directory, `${manifest.id}.vyxext`);
  const indexPath = join(directory, 'vyx-extensions.json');
  try {
    await publishPackage(output, manifest, wasm);
    const previous = await readFile(output);
    const previousIndex = await readFile(indexPath);
    for (const name of ['vyx-extensions.json', '.hidden', 'bad name.vyxext', 'bad\\name', 'a'.repeat(256)]) {
      await assert.rejects(publishPackage(join(directory, name), manifest, wasm), /basename/);
    }
    await assert.rejects(publishPackage(output, { ...manifest, apiVersion: 2 }, wasm));
    await assert.rejects(publishPackage(output, manifest, new Uint8Array(8)));
    assert.deepEqual(await readFile(output), previous);
    assert.deepEqual(await readFile(indexPath), previousIndex);
    assert.deepEqual((await readdir(directory)).sort(), [`${manifest.id}.vyxext`, 'vyx-extensions.json']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
