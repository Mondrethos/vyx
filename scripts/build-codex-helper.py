#!/usr/bin/env python3
"""Build the optional, source-pinned tool-free Vyx Codex helper; never touch ~/.codex."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import tomllib
import uuid

ROOT = Path(__file__).resolve().parent.parent
REVISION = "36650394c5b38c2990ccf2a3457165ca3e9d9726"
TAG = "rust-v0.157.1"
RUST = "1.95.0"
CAPABILITIES = {
    "protocolVersion": 1, "helper": "vyx-codex", "sourceRevision": REVISION,
    "toolPolicy": "deny-all", "configuration": "vyx-fixed-v1",
}
PINNED = {
    "app-server/src/main.rs": "0c63ad9961bd5be848d11115792914bb4d83a44b6a68eee0cb794c799a656fad",
    "app-server/src/lib.rs": "655c8f3d3c07dc4f1c340537eb7739e4e42eea7f32643b712ef2fb11710e0071",
    "app-server/src/message_processor.rs": "f1a1bb0029e7c2f46de3048cbbc52b55ccca413dacb8ce67c63796372468318f",
    "app-server/Cargo.toml": "fc4c938f1dbe246080f5bb0445eca8800d2d03fc62c33e7573869a72a8d5b87e",
    "core/src/session/session.rs": "b8c7568cb409f471ba6d511fd0d4761d8001f35e6f89eb003d444748838a7853",
    "ext/extension-api/src/tool_policy.rs": "909df60dd82a289a4fb7ae7083f56d6018e75cc1942880be14f2f51bc5e33f42",
    "login/src/server.rs": "260fe221f2bf91fd694135881d878a981a13cad3f91cc359904229b2e38cd936",
    "Cargo.toml": "fc578c2b218effa6a5dc11c83ca7cde07ff90a50d7f6c0805160e270ecb2cf4b",
    "Cargo.lock": "72efa81ed947d07ed4fbb3e10b094715ff00626126d758aaed56733c97887e5f",
}
ATTRIBUTIONS = {
    "LICENSE": "d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc",
    "NOTICE": "9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915",
}


def run(command, **kwargs):
    print("+", " ".join(map(str, command)), flush=True)
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError("pinned upstream patch anchor changed")
    return source.replace(before, after, 1)


def prepare(work):
    checkout = work / "source"
    fingerprint = hashlib.sha256()
    for path in [Path(__file__), ROOT / "scripts/codex-helper-main.rs", ROOT / "scripts/codex-helper-boundary.rs"]:
        fingerprint.update(path.read_bytes())
    fingerprint = fingerprint.hexdigest()
    marker = checkout / ".vyx-helper-source.json"
    previous = None
    if marker.exists():
        previous = json.loads(marker.read_text())
        for relative, digest in previous["patchedFiles"].items():
            if hashlib.sha256((checkout / "codex-rs" / relative).read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"prepared source was modified: {relative}")
        if previous["fingerprint"] == fingerprint:
            return checkout
    elif checkout.exists():
        raise RuntimeError("unmanaged source directory exists; select a fresh --work-dir")
    else:
        run(["git", "clone", "--depth", "1", "--branch", TAG, "--single-branch", "https://github.com/openai/codex.git", checkout])
    revision = subprocess.check_output(["git", "-C", checkout, "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise RuntimeError("upstream release tag no longer matches the reviewed source commit")
    source = checkout / "codex-rs"
    originals = {}
    for relative, digest in PINNED.items():
        data = (subprocess.check_output(["git", "-C", checkout, "show", f"HEAD:codex-rs/{relative}"])
                if previous else (source / relative).read_bytes())
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"pinned upstream source hash mismatch: {relative}")
        originals[relative] = data.decode()
    patched = dict(originals)
    patched["app-server/src/main.rs"] = (ROOT / "scripts/codex-helper-main.rs").read_text()
    patched["app-server/src/vyx_boundary.rs"] = (ROOT / "scripts/codex-helper-boundary.rs").read_text()
    # At the common startup path, create/resume/fork all capture the same immutable
    # ceiling. ExtensionData supplied by a caller cannot replace this value.
    patched["core/src/session/session.rs"] = replace_once(
        patched["core/src/session/session.rs"],
        '''        let tool_policy = thread_extension_init
            .get::<codex_extension_api::ToolPolicy>()
            .unwrap_or_else(|| {
                // Older reviewer rollouts predate the explicit startup policy.
                if crate::guardian::is_basic_session_source(&session_configuration.session_source) {
                    Arc::new(codex_guardian_reviewer::reviewer_tool_policy())
                } else {
                    Arc::default()
                }
            });''',
        '''        // Vyx-owned, unconditional ceiling for new, resumed and forked threads.
        let tool_policy = Arc::new(codex_extension_api::ToolPolicy {
            allowed_tools: Some(Vec::new()),
            require_managed_sandbox: true,
            require_unified_exec: true,
            expose_additional_permissions: false,
        });
        thread_extension_init.insert(tool_policy.as_ref().clone());''')
    patched["ext/extension-api/src/tool_policy.rs"] = replace_once(
        patched["ext/extension-api/src/tool_policy.rs"], "allowed_tools: None,", "allowed_tools: Some(Vec::new()),")
    patched["ext/extension-api/src/tool_policy.rs"] = replace_once(
        patched["ext/extension-api/src/tool_policy.rs"],
        '''    pub fn allows(&self, tool: &ToolName) -> bool {
        self.allowed_tools.as_ref().is_none_or(|tools| {
            tools.iter().any(|allowed| {
                allowed.name == tool.name
                    && (allowed.namespace == tool.namespace
                        || (allowed.is_default_namespace() && tool.is_default_namespace()))
            })
        })
    }''',
        '''    pub fn allows(&self, _tool: &ToolName) -> bool {
        // This distribution never exposes local, dynamic, MCP, or hosted tools.
        // Even an explicitly supplied alternate policy cannot widen this ceiling.
        false
    }''')
    patched["app-server/src/lib.rs"] += "\nmod vyx_boundary;\n"
    # There is no inner command runner in this distribution. Remove its startup
    # subprocess prerequisite probe, not the real config-warning machinery.
    patched["app-server/src/lib.rs"] = replace_once(
        patched["app-server/src/lib.rs"],
        '''    if let Some(warning) =
        codex_core::config::system_bwrap_warning(config.permissions.permission_profile())
    {
        config_warnings.push(ConfigWarningNotification {
            summary: warning,
            details: None,
            path: None,
            range: None,
        });
    }
''', "")
    patched["app-server/src/lib.rs"] = replace_once(
        patched["app-server/src/lib.rs"],
        '''fn loader_overrides_with_test_user_config_file(
    mut loader_overrides: LoaderOverrides,
    test_user_config_file: Option<std::path::PathBuf>,
) -> IoResult<LoaderOverrides> {
''',
        '''fn loader_overrides_with_test_user_config_file(
    loader_overrides: LoaderOverrides,
    test_user_config_file: Option<std::path::PathBuf>,
) -> IoResult<LoaderOverrides> {
    #[cfg(debug_assertions)]
    let mut loader_overrides = loader_overrides;
''')
    patched["app-server/src/message_processor.rs"] = replace_once(
        patched["app-server/src/message_processor.rs"],
        "fn deserialize_client_request(request: JSONRPCRequest) -> Result<ClientRequest, JSONRPCErrorError> {\n",
        "fn deserialize_client_request(mut request: JSONRPCRequest) -> Result<ClientRequest, JSONRPCErrorError> {\n    crate::vyx_boundary::validate_request(&mut request).map_err(invalid_request)?;\n")
    patched["app-server/Cargo.toml"] = replace_once(
        patched["app-server/Cargo.toml"], "[dependencies]\n", "[dependencies]\nlibc = { workspace = true }\n")
    patched["login/src/server.rs"] = replace_once(
        patched["login/src/server.rs"],
        '''                    // Obtain API key via token-exchange and persist
                    let api_key =
                        obtain_api_key(&client, &opts.issuer, &opts.client_id, &tokens.id_token)
                            .await
                            .ok();''',
        '''                    // Vyx uses subscription credentials only: no API-key exchange.
                    let api_key: Option<String> = None;''')
    patched["login/src/server.rs"] = replace_once(
        patched["login/src/server.rs"], "Ok((tokens, client)) => {", "Ok((tokens, _)) => {")
    exchange_start = originals["login/src/server.rs"].index("/// Exchanges an authenticated ID token for an API-key style access token.\n")
    exchange_end = originals["login/src/server.rs"].index("#[cfg(test)]\nmod tests {", exchange_start)
    patched["login/src/server.rs"] = replace_once(
        patched["login/src/server.rs"], originals["login/src/server.rs"][exchange_start:exchange_end], "")
    # The official release tag updates workspace.package.version but leaves local
    # lockfile entries at 0.0.0. Reconcile only those path packages, not dependencies.
    inherited = set()
    for manifest in source.rglob("Cargo.toml"):
        package = tomllib.loads(manifest.read_text()).get("package", {})
        if package.get("version") == {"workspace": True}:
            inherited.add(package["name"])
    def local_version(match):
        name = match[1]
        return f'name = "{name}"\nversion = "0.157.1"' if name in inherited else match[0]
    lock = re.sub(r'name = "([^"\n]+)"\nversion = "0\.0\.0"', local_version, patched["Cargo.lock"])
    start = lock.index('name = "codex-app-server"\n')
    end = lock.index("\n[[package]]", start)
    block = replace_once(lock[start:end], ' "http 1.4.0",\n', ' "http 1.4.0",\n "libc",\n')
    patched["Cargo.lock"] = lock[:start] + block + lock[end:]
    # Omit debug data and strip only the release profile, preserving other profiles.
    patched["Cargo.toml"] = replace_once(patched["Cargo.toml"], 'lto = "thin"\ndebug = "line-tables-only"', 'lto = "thin"\ndebug = "none"')
    patched["Cargo.toml"] = replace_once(patched["Cargo.toml"], "# sidecar symbols and stripped the binaries.\nstrip = false\n", '# sidecar symbols and stripped the binaries.\nstrip = "symbols"\n')
    for relative, text in patched.items():
        prefix = "//" if relative.endswith(".rs") else "#"
        text = f"{prefix} Modified by Vyx: pinned tool-free helper; recipe in scripts/build-codex-helper.py.\n" + text
        patched[relative] = text
        if previous is None or previous["patchedFiles"].get(relative) != hashlib.sha256(text.encode()).hexdigest():
            (source / relative).write_text(text)
    marker.write_text(json.dumps({"fingerprint": fingerprint, "patchedFiles": {
        relative: hashlib.sha256(text.encode()).hexdigest() for relative, text in patched.items()
    }}, indent=2) + "\n")
    return checkout


def musl_environment(target):
    """Compiler settings shared by the native and container builds."""
    key = target.replace("-", "_")
    environment = {f"CC_{key}": "musl-gcc", f"CARGO_TARGET_{key.upper()}_LINKER": "musl-gcc"}
    if target.startswith("aarch64-"):
        # GCC's default outline atomics need libgcc's LSE probe, which calls glibc's
        # __getauxval and cannot link against musl; jemalloc would then find no atomics.
        environment[f"CFLAGS_{key}"] = "-mno-outline-atomics"
    return environment


def native_build(checkout, target, jobs):
    for tool in ["cargo", "rustup", "musl-gcc", "cmake", "clang", "perl", "make", "readelf"]:
        if not shutil.which(tool):
            raise RuntimeError(f"native build requires {tool}; omit --native to use rootless podman")
    run(["rustup", "target", "add", "--toolchain", RUST, target])
    environment = os.environ.copy()
    environment.update(musl_environment(target))
    environment.update({
        "CARGO_BUILD_JOBS": str(jobs),
        "CARGO_INCREMENTAL": "0",
        "SOURCE_DATE_EPOCH": "1789603200",
    })
    # Debian musl-gcc specs otherwise inject PT_INTERP even for Rust's static PIE.
    # Apply the linker correction only to the final executable, not every dependency.
    run(["cargo", f"+{RUST}", "rustc", "--locked", "--release", "--package", "codex-app-server", "--bin", "codex-app-server", "--target", target, "--", "-C", "link-arg=-Wl,--no-dynamic-linker"], cwd=checkout / "codex-rs", env=environment)


def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise RuntimeError(f"directory must be owned by you and mode 0700: {path}")


def publish(path, data, mode):
    descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def package(binary, checkout, output, target, install):
    headers = subprocess.check_output(["readelf", "--program-headers", binary], text=True)
    dynamic = subprocess.check_output(["readelf", "--dynamic", binary], text=True)
    if "INTERP" in headers or "(NEEDED)" in dynamic:
        raise RuntimeError("helper must be static: no loader or shared-library mounts are permitted")
    capabilities = subprocess.check_output([binary, "--vyx-capabilities"], env={}, timeout=10)
    if len(capabilities) > 4096 or json.loads(capabilities) != CAPABILITIES:
        raise RuntimeError("helper capability handshake does not match the reviewed boundary")
    attributions = {}
    for name, expected in ATTRIBUTIONS.items():
        attribution = (checkout / name).read_bytes()
        if hashlib.sha256(attribution).hexdigest() != expected:
            raise RuntimeError(f"pinned upstream {name} changed")
        attributions[name] = attribution
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    record = dict(CAPABILITIES, vyxVersion=version, target=target, sha256=digest, bytes=len(data), origin="source-build")
    output.mkdir(parents=True, exist_ok=True)
    asset = output / f"vyx-codex-{target}"
    publish(asset, data, 0o700)
    publish(Path(str(asset) + ".json"), (json.dumps(record, separators=(",", ":")) + "\n").encode(), 0o600)
    for name, attribution in attributions.items():
        publish(output / f"vyx-codex-{name}", attribution, 0o600)
    print(json.dumps({"asset": str(asset), "sha256": digest, "capabilities": json.loads(capabilities)}), flush=True)
    if install:
        data_dir = install.absolute()
        private_directory(data_dir)
        directory = data_dir
        for name in ["ai", "runtime", "codex"]:
            directory /= name
            private_directory(directory)
        publish(directory / f"helper-{digest}", data, 0o700)
        for name, attribution in attributions.items():
            publish(directory / name, attribution, 0o600)
        publish(directory / "runtime.json", (json.dumps(record, separators=(",", ":")) + "\n").encode(), 0o600)
        print(f"Installed optional helper in {directory}; standalone Codex was not accessed", flush=True)


def main():
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / "target/codex-helper-build")
    parser.add_argument("--output", type=Path, default=ROOT / "target/codex-helper")
    parser.add_argument("--install-data-dir", type=Path, help="explicitly provision only Vyx's managed helper cache")
    parser.add_argument("--native", action="store_true", help="use an already provisioned native musl/Rust toolchain")
    parser.add_argument("--prepare-only", action="store_true", help="verify the pin and prepare source without compiling")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    machine = platform.machine()
    if platform.system() != "Linux" or machine not in ["x86_64", "aarch64"]:
        parser.error("the isolated helper currently supports Linux x86_64/aarch64 only")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    target = f"{machine}-unknown-linux-musl"
    work = args.work_dir.absolute()
    work.mkdir(parents=True, exist_ok=True)
    checkout = prepare(work)
    if args.prepare_only:
        print(json.dumps({"source": str(checkout), "revision": REVISION, "capabilities": CAPABILITIES}))
        return
    if args.native:
        native_build(checkout, target, args.jobs)
    else:
        engine = shutil.which("podman") or shutil.which("docker")
        if not engine:
            parser.error("install rootless podman, or prepare native tools and use --native")
        image = f"vyx-codex-builder:{RUST}"
        run([engine, "build", "--tag", image, "--file", ROOT / "scripts/codex-helper.Dockerfile", ROOT / "scripts"])
        container = f"vyx-codex-build-{uuid.uuid4().hex}"
        command = [engine, "run", "--rm", "--name", container, "--network=host", "--volume", f"{checkout}:/source:Z", "--workdir", "/source/codex-rs"]
        if Path(engine).name == "podman":
            command += ["--userns=keep-id"]
        command += ["--env", "HOME=/tmp", "--env", "CARGO_HOME=/source/.cargo-build", "--env", "CARGO_INCREMENTAL=0",
                    "--env", f"CARGO_BUILD_JOBS={args.jobs}", "--env", "SOURCE_DATE_EPOCH=1789603200"]
        for name, value in musl_environment(target).items():
            command += ["--env", f"{name}={value}"]
        command += [image, "cargo", f"+{RUST}", "rustc", "--locked", "--release", "--package", "codex-app-server", "--bin", "codex-app-server", "--target", target,
                    "--", "-C", "link-arg=-Wl,--no-dynamic-linker"]
        try:
            run(command)
        finally:
            # Interrupting the podman client alone does not stop its container.
            # Never search for or stop another build's container.
            subprocess.run([engine, "rm", "--force", container], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    binary = checkout / "codex-rs/target" / target / "release/codex-app-server"
    package(binary, checkout, args.output.absolute(), target, args.install_data_dir)


if __name__ == "__main__":
    main()
