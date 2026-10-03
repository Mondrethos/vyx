#!/usr/bin/env python3
"""Exercise a built Vyx helper offline, without authentication, inference or real account files."""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

REVISION = "36650394c5b38c2990ccf2a3457165ca3e9d9726"
EXPECTED = {"protocolVersion": 1, "helper": "vyx-codex", "sourceRevision": REVISION,
            "toolPolicy": "deny-all", "configuration": "vyx-fixed-v1"}


def command(binary, state, operation):
    # Intentionally no --share-net: neither login nor model requests are possible.
    return ["/usr/bin/bwrap", "--unshare-user", "--unshare-all", "--disable-userns",
            "--assert-userns-disabled", "--die-with-parent", "--new-session", "--clearenv",
            "--cap-drop", "ALL", "--hostname", "vyx-codex-smoke", "--ro-bind", str(binary), "/vyx-codex",
            "--dir", "/home", "--dir", "/work", "--dir", "/proc", "--dir", "/proc/self",
            "--symlink", "/vyx-codex", "/proc/self/exe", "--bind", state, "/state", "--tmpfs", "/tmp",
            "--setenv", "HOME", "/home", "--setenv", "CODEX_HOME", "/state",
            "--setenv", "TMPDIR", "/tmp", "--setenv", "PATH", "/nonexistent",
            "--setenv", "RUST_LOG", "off", "--setenv", "OTEL_SDK_DISABLED", "true",
            "--setenv", "VYX_CODEX_SANDBOX", "1", "--chdir", "/work", "--remount-ro", "/",
            "/vyx-codex", operation]


async def smoke(binary):
    record = json.loads(Path(str(binary) + ".json").read_text())
    digest = hashlib.file_digest(binary.open("rb"), "sha256").hexdigest()
    assert record["sha256"] == digest and record["sourceRevision"] == REVISION
    with tempfile.TemporaryDirectory(prefix="vyx-codex-smoke-", dir="/dev/shm") as state:
        (Path(state) / "read-proof").write_text("explicit smoke fixture; no account material")
        result = subprocess.run(command(binary, state, "--vyx-capabilities"), env={},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=15)
        assert len(result.stdout) <= 4096 and json.loads(result.stdout) == EXPECTED
        process = await asyncio.create_subprocess_exec(
            *command(binary, state, "app-server"), env={}, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=1024 * 1024)
        request_id = 0
        notices = set()

        async def request(method, params, rejected=False):
            nonlocal request_id
            request_id += 1
            process.stdin.write(json.dumps({"id": request_id, "method": method, "params": params}).encode() + b"\n")
            await process.stdin.drain()
            for _ in range(256):
                line = await asyncio.wait_for(process.stdout.readline(), timeout=30)
                assert line, f"helper exited during {method}"
                frame = json.loads(line)
                assert not ("method" in frame and "id" in frame), "helper requested a client-side tool"
                if "method" in frame:
                    notices.add(frame["method"])
                    assert frame["method"] != "configWarning", "fixed helper configuration is invalid"
                if frame.get("id") != request_id:
                    continue
                assert ("error" in frame) == rejected, f"unexpected result for {method}"
                return frame.get("result")
            raise AssertionError("unbounded helper notification flood")

        try:
            initialized = await request("initialize", {"clientInfo": {"name": "vyx", "version": "smoke"},
                                                       "capabilities": {"experimentalApi": True}})
            assert "0.157.1" in initialized["userAgent"]
            process.stdin.write(b'{"method":"initialized","params":{}}\n')
            await process.stdin.drain()
            account = await request("account/read", {"refreshToken": False})
            assert account["account"] is None and account["requiresOpenaiAuth"] is True
            await request("command/exec", {"command": ["/bin/sh", "-c", "id"]}, rejected=True)
            await request("fs/readFile", {"path": "/state/read-proof"}, rejected=True)
            await request("config/value/write", {"keyPath": "model_provider", "value": "other", "mergeStrategy": "replace"}, rejected=True)
            await request("thread/start", {"config": {"chatgpt_base_url": "http://127.0.0.1/"}}, rejected=True)
            await request("thread/start", {"dynamicTools": [{"name": "read_file", "description": "forbidden", "inputSchema": {}}]}, rejected=True)
            await request("turn/start", {"threadId": "no-thread", "input": [{"type": "localImage", "path": "/state/auth.json"}]}, rejected=True)
            thread = await request("thread/start", {
                "model": "gpt-5.5", "modelProvider": "openai", "allowProviderModelFallback": False,
                "cwd": "/work", "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": True,
                "baseInstructions": "Only explicitly supplied text is available.", "developerInstructions": "",
                "environments": [], "dynamicTools": [], "selectedCapabilityRoots": [],
            })
            thread_id = thread["thread"]["id"]
            assert thread["modelProvider"] == "openai" and thread["cwd"] == "/work"
            assert thread["thread"]["ephemeral"] is True and thread["thread"]["path"] is None
            await request("thread/inject_items", {"threadId": thread_id, "items": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Explicit prior question."}]},
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Explicit prior answer."}]},
            ]})
            await request("thread/inject_items", {"threadId": thread_id, "items": [
                {"type": "function_call", "name": "apply_patch", "arguments": "forbidden", "call_id": "blocked"},
            ]}, rejected=True)
            assert not (Path(state) / "config.toml").exists(), "rejected configuration write changed state"
            assert not (Path(state) / "auth.json").exists(), "offline smoke created unexpected credentials"
            print(json.dumps({"capabilities": EXPECTED, "sha256": digest, "account": None,
                              "ephemeralThread": True, "explicitTextHistory": True,
                              "commandFilesystemConfigurationToolsAndFileInput": "rejected",
                              "network": "unshared", "login": "not attempted", "inference": "not attempted",
                              "notifications": sorted(notices)}, sort_keys=True))
        finally:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await asyncio.wait_for(process.wait(), timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="built helper with its .json metadata sidecar")
    args = parser.parse_args()
    asyncio.run(smoke(args.binary.resolve()))


if __name__ == "__main__":
    main()
