import { builtinModules, isBuiltin } from 'node:module';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { watch } from 'node:fs';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';
import ts from 'typescript';
import { validateManifest, type Manifest } from './manifest.js';
import { check, jsonBytes, object, parseJson } from './validation.js';

const JAVY_RELEASE = 'https://github.com/bytecodealliance/javy/releases/tag/v9.1.0';
export interface BuildOptions { project: string; out?: string; id?: string; javy?: string }
async function command(executable: string, args: string[]): Promise<string> {
  const { promise, resolve: accept, reject } = Promise.withResolvers<string>();
  const child = spawn(executable, args, { stdio: ['ignore', 'pipe', 'pipe'], shell: false });
  let stdout = ''; let stderr = ''; let size = 0;
  const timeout = setTimeout(() => child.kill('SIGKILL'), 120000);
  const receive = (chunk: Buffer, error: boolean): void => {
    size += chunk.length;
    if (size > 1024 * 1024) child.kill('SIGKILL');
    else if (error) stderr += chunk.toString(); else stdout += chunk.toString();
  };
  child.stdout.on('data', (chunk: Buffer) => receive(chunk, false));
  child.stderr.on('data', (chunk: Buffer) => receive(chunk, true));
  child.on('error', error => { clearTimeout(timeout); reject(error); });
  child.on('close', (code, signal) => {
    clearTimeout(timeout);
    if (code === 0 && size <= 1024 * 1024) accept(stdout.trim());
    else reject(new Error(`${executable} failed (${signal ?? code}): ${stderr.slice(0, 8192)}`));
  });
  return promise;
}
export async function pinnedJavy(executable = 'javy'): Promise<string> {
  try {
    const version = await command(executable, ['--version']);
    check(/^javy\s+9\.1\.0$/u.test(version), `Expected Javy 9.1.0, received ${version}`);
    return executable;
  } catch (error) {
    throw new Error(`Javy 9.1.0 is required. Install the official author tool from ${JAVY_RELEASE}. Linux binaries require glibc 2.35+. ${String(error)}`);
  }
}
/** Same-directory fsync + rename means host watchers never see partial packages. */
export async function atomicPublish(path: string, bytes: Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${randomUUID()}.tmp`);
  try {
    const file = await open(temporary, 'wx', 0o600);
    try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
    await rename(temporary, path);
    const directory = await open(dirname(path), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await rm(temporary, { force: true }); }
}
/** Fixed container; no archives, scripts, source maps or author paths are shipped. */
export function encodePackage(manifest: Manifest, wasm: Uint8Array): Uint8Array {
  validateManifest(manifest);
  check(wasm.length >= 8 && wasm.length <= 8 * 1024 * 1024, 'Wasm size must be 8 bytes to 8 MiB');
  check(Buffer.from(wasm.subarray(0, 8)).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0])), 'Expected a static core Wasm module');
  const metadata = jsonBytes(manifest, 65536);
  const container = Buffer.alloc(16 + metadata.length + wasm.length);
  container.write('VYXEXT1\n', 0, 'ascii');
  container.writeUInt32LE(metadata.length, 8); container.writeUInt32LE(wasm.length, 12);
  container.set(metadata, 16); container.set(wasm, 16 + metadata.length);
  return container;
}
/** Publish the immutable package first, then its GitHub Release discovery index.
 * Each file is replaced atomically; upload both completed outputs to one release.
 */
export async function publishPackage(output: string, manifest: Manifest, wasm: Uint8Array): Promise<void> {
  const asset = basename(output);
  check(/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(asset) && Buffer.byteLength(asset) <= 255
    && asset !== 'vyx-extensions.json', 'Output must have a safe release asset basename other than vyx-extensions.json');
  const bytes = encodePackage(manifest, wasm);
  const index = jsonBytes({
    schemaVersion: 1,
    extensions: [{ manifest, asset, sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length }],
  }, 256 * 1024);
  await atomicPublish(output, bytes);
  await atomicPublish(join(dirname(output), 'vyx-extensions.json'), index);
}
async function loadManifest(options: BuildOptions): Promise<Manifest> {
  const bytes = await readFile(join(options.project, 'vyx.extension.json'));
  check(bytes.length <= 65536, 'Manifest size limit exceeded');
  const value = object(parseJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  if (options.id !== undefined) value.id = options.id;
  validateManifest(value);
  return value;
}
/** Syntax-aware rejection covers nonliteral imports that bundlers cannot resolve. */
export const sandboxImports: esbuild.Plugin = {
  name: 'vyx-sandbox-imports',
  setup(build) {
    build.onResolve({ filter: /.*/ }, args => {
      if (args.kind === 'dynamic-import') return { errors: [{ text: 'Dynamic imports are not supported by Vyx extensions' }] };
      if (isBuiltin(args.path) || builtinModules.includes(args.path)) return { errors: [{ text: `Node built-in ${args.path} is unavailable in Vyx` }] };
      return undefined;
    });
    build.onLoad({ filter: /\.[cm]?[jt]sx?$/ }, async args => {
      const source = await readFile(args.path, 'utf8');
      const file = ts.createSourceFile(args.path, source, ts.ScriptTarget.ESNext, true);
      let invalid = false;
      const inspect = (node: ts.Node): void => {
        if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require' && (node.arguments.length !== 1 || !ts.isStringLiteral(node.arguments[0]!))))) invalid = true;
        ts.forEachChild(node, inspect);
      };
      inspect(file);
      if (invalid) return { errors: [{ text: `Dynamic imports/requires are not supported: ${args.path}` }] };
      const extension = extname(args.path);
      const loader: esbuild.Loader = extension === '.tsx' ? 'tsx' : /\.[cm]?ts$/u.test(extension) ? 'ts' : extension === '.jsx' ? 'jsx' : 'js';
      return { contents: source, loader };
    });
  },
};
export async function buildExtension(options: BuildOptions, development = false): Promise<(() => Promise<void>) | undefined> {
  check(process.versions.node.split('.')[0] === '24', 'Extension author tooling requires Node 24 LTS');
  options = { ...options, project: resolve(options.project) };
  const executable = await pinnedJavy(options.javy);
  await loadManifest(options);
  const typescriptEntry = await stat(join(options.project, 'src/index.ts')).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  });
  const entry = typescriptEntry?.isFile() ? './src/index.ts' : './src/index.js';
  const work = join(options.project, '.vyx-build');
  await mkdir(work, { recursive: true });
  const bundle = join(work, 'bundle.js');
  const runtime = fileURLToPath(new URL('./runtime.js', import.meta.url));
  let failure: Error | undefined;
  const adapter: esbuild.Plugin = {
    name: 'vyx-entry-adapter',
    setup(build) {
      build.onResolve({ filter: /^vyx:setup$/ }, () => ({ path: 'setup', namespace: 'vyx' }));
      build.onLoad({ filter: /.*/, namespace: 'vyx' }, () => ({
        contents: `import {installConsole,guestIO} from ${JSON.stringify(runtime)}; installConsole(guestIO());`, loader: 'js', resolveDir: options.project,
      }));
      build.onEnd(async result => {
        if (result.errors.length) return;
        const wasmPath = join(work, `${randomUUID()}.wasm`);
        try {
          const manifest = await loadManifest(options);
          // The pinned default plugin already enables stream I/O and text encoding.
          // A single JS override avoids Javy 9.1.0's randomized HashMap JSON order
          // leaking into its initialized memory snapshot, even in deterministic mode.
          await command(executable, ['build', bundle, '-C', 'deterministic=y', '-J', 'event-loop=y', '-o', wasmPath]);
          const wasm = await readFile(wasmPath);
          const output = options.out === undefined ? join(options.project, 'dist', `${manifest.id}.vyxext`) : resolve(options.project, options.out);
          await publishPackage(output, manifest, wasm);
          console.log(`Built ${output} and ${join(dirname(output), 'vyx-extensions.json')}${development ? ' (development: load explicitly in Settings / Extensions)' : ' (upload both files to the same GitHub Release)'}`);
          failure = undefined;
        } catch (error) {
          failure = error instanceof Error ? error : new Error(String(error));
          if (development) console.error(failure.message);
          else return { errors: [{ text: failure.message }] };
        } finally { await rm(wasmPath, { force: true }); }
        return undefined;
      });
    },
  };
  const config: esbuild.BuildOptions = {
    absWorkingDir: options.project,
    stdin: {
      contents: `import 'vyx:setup'; import extension from ${JSON.stringify(entry)}; import {run,guestIO} from ${JSON.stringify(runtime)}; run(extension,guestIO()).catch(error=>{console.error(error);throw error;});`,
      resolveDir: options.project, sourcefile: 'vyx-entry.js', loader: 'js',
    },
    bundle: true, format: 'esm', platform: 'neutral', target: 'es2023', outfile: bundle,
    sourcemap: 'external', sourcesContent: true, metafile: true,
    mainFields: ['module', 'main'], conditions: ['import'],
    plugins: [adapter, sandboxImports], logLevel: 'warning',
  };
  if (!development) { await esbuild.build(config); if (failure) throw failure; return undefined; }
  const context = await esbuild.context(config);
  // esbuild observes the dependency graph; parent-directory watching also catches
  // atomic manifest replacement rather than staying attached to the old inode.
  let debounce: NodeJS.Timeout | undefined;
  const watcher = watch(options.project, (_event, name) => {
    if (name !== 'vyx.extension.json') return;
    clearTimeout(debounce);
    debounce = setTimeout(() => { void context.rebuild().catch(error => console.error(String(error))); }, 150);
  });
  await context.watch();
  return async () => { clearTimeout(debounce); watcher.close(); await context.dispose(); };
}
