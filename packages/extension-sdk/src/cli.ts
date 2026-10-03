#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildExtension, type BuildOptions } from './tooling.js';
import { validateManifest, type Manifest } from './manifest.js';
import { check } from './validation.js';

const help = `Vyx extension SDK (Node 24 LTS, Javy 9.1.0)
  vyx-extension init <directory> --id org.example.extension [--sdk <tarball-or-directory>]
  vyx-extension build [--project <directory>] [--out <file>] [--id <override>] [--javy <executable>]
  vyx-extension pack  [same options as build]
  vyx-extension dev   [same options as build]

build and pack bundle src/index.ts, compile static Wasm and atomically publish
  dist/<manifest-id>.vyxext and its vyx-extensions.json release index.
  --out places the index beside the custom package, using its exact asset basename.
  Upload both completed files to the same GitHub Release. No source maps enter packages.
  Example (run explicitly after creating a release):
    gh release upload <tag> dist/<manifest-id>.vyxext dist/vyx-extensions.json --repo <owner/repo>
dev watches dependencies and the manifest without launching Vyx or accessing a vault.
Load its output explicitly through Settings / Extensions / Load development package.
Use --id dev.vyx.tailscale when developing the reserved first-party source.
No install hooks run. Build maps remain in the project's .vyx-build directory.
Javy: https://github.com/bytecodealliance/javy/releases/tag/v9.1.0
Official Javy Linux author binaries require glibc 2.35+; end users need neither tool.`;

async function main(): Promise<void> {
  check(process.versions.node.split('.')[0] === '24', 'Node 24 LTS is required');
  const [operation, ...args] = process.argv.slice(2);
  if (!operation || operation === '--help' || operation === '-h') { console.log(help); return; }
  if (operation === '--version') { console.log('0.1.0'); return; }
  check(['init', 'build', 'pack', 'dev'].includes(operation), `Unknown operation ${operation}\n${help}`);
  const flags: Record<string, string> = {};
  let directory: string | undefined;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (!arg.startsWith('--')) { check(directory === undefined && operation === 'init', 'Unexpected positional argument'); directory = arg; continue; }
    check(['--id', '--out', '--project', '--javy', '--sdk'].includes(arg), `Unknown option ${arg}`);
    check(!Object.hasOwn(flags, arg), `Duplicate option ${arg}`);
    const value = args[++index]; check(value !== undefined && !value.startsWith('--'), `Missing value for ${arg}`);
    flags[arg] = value;
  }
  if (operation === 'init') {
    check(directory && flags['--id'], 'init requires a directory and --id');
    check(!flags['--out'] && !flags['--project'] && !flags['--javy'], 'Unsupported init option');
    const manifest: Manifest = {
      schemaVersion: 1, apiVersion: 1, id: flags['--id'], name: 'My Vyx extension',
      description: 'A host/session browser demonstrating reviewed proposals and local view state', version: '0.1.0',
      permissions: ['hosts.read', 'sessions.read', 'connections.propose', 'terminal.propose'],
      commands: [{ id: 'browse', title: 'Browse hosts and sessions', description: 'An example with list, detail and form views' }],
    };
    validateManifest(manifest);
    const path = resolve(directory);
    // Refuse existing destinations: scaffolding must not overwrite author work.
    await mkdir(path);
    await mkdir(resolve(path, 'src'));
    const sdk = flags['--sdk'] ? resolve(flags['--sdk']) : fileURLToPath(new URL('../', import.meta.url));
    const project = {
      name: manifest.id, version: manifest.version, private: true, type: 'module',
      engines: { node: '>=24 <25' },
      scripts: { build: 'vyx-extension build', dev: 'vyx-extension dev', typecheck: 'tsc --noEmit' },
      dependencies: { '@vyx/extension-sdk': `file:${sdk}` }, devDependencies: { typescript: '5.9.3' },
    };
    const config = {
      compilerOptions: { target: 'ES2023', module: 'ESNext', moduleResolution: 'Bundler', lib: ['ES2023'], strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true, noEmit: true, types: [] },
      include: ['src/**/*.ts'],
    };
    await writeFile(resolve(path, 'package.json'), JSON.stringify(project, null, 2) + '\n', { flag: 'wx' });
    await writeFile(resolve(path, 'tsconfig.json'), JSON.stringify(config, null, 2) + '\n', { flag: 'wx' });
    await writeFile(resolve(path, 'vyx.extension.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
    await writeFile(resolve(path, '.gitignore'), 'node_modules/\ndist/\n.vyx-build/\n', { flag: 'wx' });
    await writeFile(resolve(path, 'src/index.ts'), await readFile(new URL('../templates/index.ts', import.meta.url)), { flag: 'wx' });
    console.log(`Created ${path}. Run npm install --ignore-scripts, then npm run typecheck and npm run build in that directory. SDK dependency uses ${sdk}; --sdk can select the release tarball.`);
    return;
  }
  check(flags['--sdk'] === undefined, '--sdk is only for init');
  const options: BuildOptions = { project: flags['--project'] ?? process.cwd() };
  if (flags['--id'] !== undefined) options.id = flags['--id'];
  if (flags['--out'] !== undefined) options.out = flags['--out'];
  if (flags['--javy'] !== undefined) options.javy = flags['--javy'];
  const stop = await buildExtension(options, operation === 'dev');
  if (stop) {
    let closing = false;
    const close = (): void => {
      if (closing) return; closing = true;
      void stop().catch(error => { console.error(String(error)); process.exitCode = 1; });
    };
    process.once('SIGINT', close); process.once('SIGTERM', close);
  }
}
void main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
