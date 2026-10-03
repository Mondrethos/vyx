#!/usr/bin/env python3
"""Run the release's real Javy package in its native worker, using only fake status.

No Tailscale CLI, vault, SSH connection, Node, or Javy is used by this smoke.
The final proposal is inspected, never approved or executed. Timings measure
this invocation, not a historical performance baseline.
"""

import argparse
import asyncio
import hashlib
import json
import pathlib
import struct
import sys
import time


MAX_MANIFEST = 64 * 1024
MAX_WASM = 8 * 1024 * 1024
MAX_FRAME = 1024 * 1024
START_TIMEOUT = 20
EVENT_TIMEOUT = 10
NODE_REF = "release-fixture-node"
ADDRESS = "100.64.0.42"
DNS_NAME = "release-fixture.example.ts.net"
STATUS = {
    "state": "running",
    "tailnetName": "release-fixture",
    "peers": [{
        "nodeRef": NODE_REF,
        "name": "Release fixture",
        "dnsName": DNS_NAME,
        "addresses": [ADDRESS],
        "online": True,
        "os": "linux",
        "tags": ["tag:release-fixture"],
        "sshHostKeysAvailable": True,
    }],
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key from worker/package")
        result[key] = value
    return result


def reject_constant(value):
    raise RuntimeError(f"non-JSON numeric constant: {value}")


def parse_json(data):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 32, "JSON nesting exceeds protocol limit")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def load_package(path):
    require(16 < path.stat().st_size <= 16 + MAX_MANIFEST + MAX_WASM,
            "invalid package size")
    data = path.read_bytes()
    require(data[:8] == b"VYXEXT1\n", "invalid package magic")
    manifest_size, wasm_size = struct.unpack("<II", data[8:16])
    require(0 < manifest_size <= MAX_MANIFEST, "invalid manifest length")
    require(0 < wasm_size <= MAX_WASM, "invalid Wasm length")
    require(len(data) == 16 + manifest_size + wasm_size,
            "truncated package or trailing bytes")
    manifest = parse_json(data[16:16 + manifest_size])
    require(manifest.get("id") == "com.vyx.tailscale"
            and manifest.get("schemaVersion") == 1
            and manifest.get("apiVersion") == 1,
            "expected the API-1 release Tailscale package")
    require(any(command.get("id") == "browse" for command in manifest["commands"]),
            "release browser command is missing")
    wasm = data[16 + manifest_size:]
    require(wasm[:8] == b"\0asm\x01\0\0\0", "expected a core Wasm module")
    digest = hashlib.sha256(data).hexdigest()
    index_path = path.with_name("vyx-extensions.json")
    require(0 < index_path.stat().st_size <= 256 * 1024, "invalid release index size")
    index = parse_json(index_path.read_bytes())
    require(isinstance(index, dict) and index.get("schemaVersion") == 1
            and isinstance(index.get("extensions"), list), "invalid release index")
    matches = [entry for entry in index["extensions"]
               if isinstance(entry, dict)
               and entry.get("manifest", {}).get("id") == manifest["id"]]
    require(matches == [{"manifest": manifest, "asset": path.name,
                         "sha256": digest, "size": len(data)}],
            "release index does not describe the exact canonical package")
    return wasm, digest


def frame(value):
    data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")
    require(0 < len(data) <= MAX_FRAME, "outbound frame exceeds limit")
    return struct.pack("<I", len(data)) + data


async def receive(reader):
    length, = struct.unpack("<I", await reader.readexactly(4))
    require(0 < length <= MAX_FRAME, "worker frame exceeds limit")
    value = parse_json(await reader.readexactly(length))
    require(isinstance(value, dict), "worker frame must be an object")
    return value


async def drain_diagnostics(reader, ring):
    while chunk := await reader.read(8192):
        ring.extend(chunk)
        del ring[:-65536]


async def version(binary, name):
    began = time.perf_counter()
    process = await asyncio.create_subprocess_exec(
        str(binary), "--version", cwd="/", env={"PATH": "/nonexistent"},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, close_fds=True,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), START_TIMEOUT)
        require(process.returncode == 0, f"{name} --version failed: {stderr!r}")
        fields = stdout.decode("utf-8").strip().split()
        require(len(fields) == 2 and fields[0] == name, f"unexpected {name} version output")
        return fields[1], round((time.perf_counter() - began) * 1000, 3)
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


async def smoke(core, worker, package):
    wasm, digest = load_package(package)
    require(0 < worker.stat().st_size <= 128 * 1024 * 1024,
            "worker exceeds the managed runtime download limit")
    runtime_version, core_version_ms = await version(core, "vyx")
    worker_version, worker_version_ms = await version(worker, "vyx-extension-worker")
    require(runtime_version == worker_version, "core and worker release versions differ")
    started = time.perf_counter()
    process = await asyncio.create_subprocess_exec(
        str(worker), cwd="/", env={"PATH": "/nonexistent"},
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, close_fds=True,
    )
    diagnostics = bytearray()
    diagnostic_task = asyncio.create_task(drain_diagnostics(process.stderr, diagnostics))
    timings = []
    request_counts = []
    last_request = 0

    async def bootstrap():
        process.stdin.write(frame({"protocolVersion": 2, "runtimeVersion": runtime_version}))
        process.stdin.write(struct.pack("<I", len(wasm)))
        process.stdin.write(wasm)
        await process.stdin.drain()
        require(await receive(process.stdout) == {"kind": "ready"},
                "worker did not report successful compilation/readiness")

    async def event(event_id, payload, state, expected_requests):
        nonlocal last_request
        process.stdin.write(frame({"kind": "event", "id": event_id,
                                   "event": payload, "state": state}))
        await process.stdin.drain()
        calls = 0
        while True:
            message = await receive(process.stdout)
            require(type(message.get("eventId")) is int
                    and message["eventId"] == event_id, "wrong worker event identity")
            if message.get("kind") == "request":
                require(set(message) == {"kind", "eventId", "id", "method"},
                        "unexpected request fields")
                request_id = message["id"]
                require(type(request_id) is int and last_request < request_id <= 2**53 - 1,
                        "non-monotonic worker request identity")
                require(message["method"] == "tailscale.status", "unexpected broker capability")
                calls += 1
                require(calls <= expected_requests, "unexpected extra broker request")
                last_request = request_id
                process.stdin.write(frame({"kind": "response", "eventId": event_id,
                                           "id": request_id, "value": STATUS}))
                await process.stdin.drain()
            else:
                require(set(message) == {"kind", "eventId", "result"}
                        and message["kind"] == "result", "worker failed to complete an event")
                require(calls == expected_requests, "missing asynchronous broker request")
                result = message["result"]
                require(isinstance(result, dict) and "view" in result
                        and set(result) <= {"view", "state", "proposal"},
                        "invalid extension result envelope")
                request_counts.append(calls)
                return result

    async def timed_event(event_id, payload, state, expected_requests):
        began = time.perf_counter()
        result = await asyncio.wait_for(event(event_id, payload, state, expected_requests),
                                        EVENT_TIMEOUT)
        timings.append(round((time.perf_counter() - began) * 1000, 3))
        return result

    try:
        await asyncio.wait_for(bootstrap(), START_TIMEOUT)
        startup_ms = round((time.perf_counter() - started) * 1000, 3)
        opened = await timed_event(1, {"kind": "open", "commandId": "browse",
                                      "reason": "launch"}, {}, 1)
        require("proposal" not in opened, "opening the browser proposed an action")
        view = opened["view"]
        require(view["kind"] == "list" and view["searchable"] is True,
                "browser did not render a searchable list")
        require(len(view["items"]) == 1, "fixture catalog did not render exactly one peer")
        item = view["items"][0]
        require(item["id"] == f"{NODE_REF}|{ADDRESS}" and "details" in item["actions"],
                "browser lost the fixture device identity")
        details = await timed_event(2, {"kind": "action", "actionId": "details",
                                       "itemId": item["id"]}, opened["state"], 1)
        require("proposal" not in details and details["view"]["kind"] == "detail",
                "device inspection must not propose a connection")
        require(any(field["value"] == DNS_NAME for field in details["view"]["fields"]),
                "refreshed fixture metadata is missing")
        # A fresh Wasm Store has no previous JS globals. This action can succeed
        # only by consuming the selection in the previous event's returned state.
        proposed = await timed_event(3, {"kind": "action", "actionId": "connect-keyless"},
                                    details["state"], 0)
        require(proposed.get("proposal") == {"kind": "connect-tailnet", "nodeRef": NODE_REF,
                                             "mode": "tailscale-ssh"},
                "cross-event state did not retain the exact selected device")
        require(proposed["view"] == details["view"], "proposal replaced its reviewed detail view")
        try:
            extra = await asyncio.wait_for(process.stdout.read(1), 0.05)
        except asyncio.TimeoutError:
            pass
        else:
            require(False, "worker exited unexpectedly" if not extra else "extra worker output")
        return {
            "coreBinary": str(core), "coreBytes": core.stat().st_size,
            "workerBinary": str(worker), "workerBytes": worker.stat().st_size,
            "coreVersionStartupMs": core_version_ms, "workerVersionStartupMs": worker_version_ms,
            "runtimeVersion": runtime_version, "protocolVersion": 2,
            "packageSha256": digest, "packageBytes": package.stat().st_size,
            "environmentPath": "/nonexistent",
            "compileAndWorkerStartupMs": startup_ms, "eventMs": timings,
            "brokerRequestsPerEvent": request_counts,
            "events": ["open", "fresh-details", "state-restored-proposal"],
            "fixtureOnly": True, "historicalBaseline": None,
        }
    except Exception as error:
        # JSON escaping prevents any terminal controls in diagnostics being emitted raw.
        raise RuntimeError(f"{type(error).__name__}: {error}; worker diagnostics="
                           f"{json.dumps(diagnostics.decode('utf-8', errors='replace'))}") from error
    finally:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
        await diagnostic_task


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("core", type=pathlib.Path)
    parser.add_argument("worker", type=pathlib.Path)
    parser.add_argument("package", type=pathlib.Path)
    args = parser.parse_args()
    result = asyncio.run(smoke(args.core.resolve(strict=True), args.worker.resolve(strict=True),
                              args.package.resolve(strict=True)))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Extension runtime smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
