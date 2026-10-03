# Vyx

Vyx is an encrypted SSH workspace.

## Setup

On a new data directory, choose **Set up Vyx**. The guide creates local encrypted storage (**Storage**), asks for a **New passphrase** of at least 16 characters, offers **Recovery options**, and ends on **Ready** with getting-started instructions. To synchronize, connect the vault later under **Settings / Vault synchronization**. **Restore from server** and **Restore encrypted file** remain available on the welcome screen.

Recovery export asks for the current passphrase again. Choose a new absolute filename outside the vault directory (`~` is not expanded) and confirm separate storage. Anyone with both the recovery file and encrypted vault can access the vault. A recovery file is not a data backup; keep it offline or in a password manager, separate from the vault. Changing the passphrase invalidates previous recovery files.

Export errors leave the form editable. A durability warning means the file was installed, but its durability could not be fully confirmed; read the warning before proceeding. Do not retry the same filename. Skipping export or choosing **Finish later** does not undo vault creation. A forgotten passphrase cannot be reset without a matching recovery file.

## Rerun the guide

Open **Settings / Setup wizard** to review storage, recovery protection, and getting started. This does not recreate the vault, change preferences or synchronization, or reconnect SSH sessions. Synchronized vaults show their existing mode and omit local recovery export.

The guide stores no completion marker or recovery receipt. It opens automatically only immediately after new-vault creation; subsequent launches unlock normally. Leaving the Setup section discards its unfinished form, including any entered passphrase. Recovery export is also available directly under **Settings / Security / Save recovery file**.

Add connections from **Servers**; an empty workspace selects it and offers **Add server**. The footer keeps **Commands** (the prefix bar, **Ctrl+B** by default), **Settings**, and **Shortcuts** in reach.

## Workspace

The single **Search** control at the top of the sidebar filters names and metadata as you type and selects the first match. Enter or Tab keeps the filter; clicking a row keeps it and acts on that row. With a kept filter, Esc (outside search) or the **Clear** control removes it and restores the earlier selection. Section labels show total counts, and an empty result says **No matches**. Saving a server reveals and selects its row, including inside categories.

The tab strip's **Layout** button cycles Single, Side by side, Stacked, and Grid and saves the choice (also **Ctrl+B, then l**); clicking a tab only focuses it. An ended session shows **Reconnect** and **Close** on its pane; reconnecting replaces the same tab. While scrolled back, the pane shows **Scrollback +N · type to return**, and typing returns to the live screen before anything is sent. Below 40×10 cells, Vyx shows the current and required size with the detach and quit keys until the window grows.

## Settings

Settings sections are Workspace, Themes, Security, Keyboard shortcuts, Vault synchronization, Tailscale transport, Setup wizard, and Extensions; enabled extension packages appear beneath Extensions. Titles read as breadcrumbs (`Settings / Security / Auto-lock`) and drop leading parts only when narrow. Short choices are inline segments (click one or use Left/Right), checkboxes toggle with Space or a click, and read-only identity fields show no arrows and are skipped by Tab. While the section list has the keyboard, the page beside it shows no cursor or focus marker; press Enter or click a control to edit it. Long errors wrap without hiding the buttons, and a form whose fields do not fit shows the visible range and a scrollbar.

Workspace, Vault synchronization, Tailscale transport, and Security forms keep a draft until you save it: clicking another section keeps the draft, and Esc or **Discard** discards it. Themes, the shortcut list, and Extensions apply each action as you choose it. Workspace settings cover sidebar width and visibility, terminal layout, icon mode, and animation; key bindings remain customizable.

## Session names

Click **Rename** on the active session tab, or right-click any tab or session in the sidebar. You can also select a sidebar session and use **Rename** in its Actions area or the configured Edit shortcut (`e` by default). Narrow tabs omit the button; right-click and the sidebar action remain available.

Enter a nonblank name and choose **Rename**, or cancel to keep the existing name. The tab, terminal heading, and sidebar update together without reconnecting SSH or changing the saved server. Names belong to individual open sessions, including ended sessions that have not been dismissed. They survive detach/reattach, but closing the session or quitting the workspace discards them; a new connection, including **Reconnect**, starts with the saved server name. When that name is already used by another live tab, the new tab gets the smallest free suffix, such as `web (2)`; saved servers are never renamed.

## Extensions

The core Vyx executable contains no extension packages or WebAssembly engine. SSH, vaults, and other core features remain standalone. Open **Settings / Extensions** to browse the official GitHub Release catalog, add another GitHub repository, or install a local `.vyxext` package. Catalog entries show their manifest, release source, download size, SHA-256, and permissions before download. Browsing and downloading do not run extension code or grant permissions.

Every installed package—enabled, disabled, or development—is listed on **Settings / Extensions**, which also opens the catalog and package manager. Enabled packages additionally get an indented entry under the **Extensions** category, using their manifest name and stable ID. Select a package to review permissions, updates, removal, and diagnostics without launching guest code. Long extension lists remain keyboard- and mouse-scrollable at narrow terminal sizes.

Installation reviews and copies an immutable snapshot, then opens that package's page; a new package stays disabled until you choose **Review and enable** and approve its permissions. Approving a reviewed update grants the listed permissions to the new digest and enables it, and also lands on the package's page. **Disable** asks for confirmation (**Disable extension**); the package's sidebar entry disappears at once, its details stay open under Extensions, and SSH sessions are unaffected. Enabling again repeats the permission review. SDK packages use an optional, Vyx-managed native worker: first enable reviews its version, platform, official release, size, and SHA-256 before downloading. **Vyx AI** is a native integration and does not download or start that worker. No Node.js, Javy, or system runtime installation is needed. Open enabled commands with **Ctrl+B, then e** by default; this binding is configurable in Shortcuts. The picker reads manifests without starting extensions.

**Vyx release** means the package came from the official `Mondrethos/vyx` release catalog. Other GitHub publishers and local packages are **Unverified**: names, versions, and hashes do not authenticate a publisher. Production updates require review of the new digest and permission changes. Downloads are explicit; there are no install hooks or startup update checks. A failed or cancelled download cannot enable a package. Packages retained from older bundled releases are disabled with grants cleared; update them from the official catalog before enabling, or remove them.

| Permission | Available data or proposed action |
| --- | --- |
| `hosts.read` | Saved host IDs, labels, addresses, ports, categories, and authentication-mode labels—not authentication values. |
| `sessions.read` | Session UUIDs, labels, optional saved-host IDs, and phases—not terminal contents. |
| `tailscale.read` | Normalized local status and peer metadata with opaque, short-lived references—not raw status, account identities, host keys, or authentication URLs. |
| `terminal.propose` | Request exact-text insertion into an explicitly reviewed session. |
| `connections.propose` | Request a reviewed saved-server or Tailscale connection. |
| `hosts.propose` | Request an explicitly saved Tailscale server draft. |

Declaring a permission does not grant it. Every call and proposal is checked against the current package and grants. Extensions never receive vault keys, passwords, private keys, SSH-agent descriptors, terminal streams, or a generic command-execution API. Forms rendered for an extension explicitly warn that the extension can read entered values; do not enter credentials there. Connection credentials belong only in Vyx-owned dialogs.

Extension actions can open a host-owned review, but cannot approve it. **Insert without Enter** shows the full command, session UUID, and endpoint; changing tabs cannot retarget it. Cancellation sends nothing, and disconnected targets are rejected. Vyx inserts the reviewed single-line text without an execution key; a remote application can still interpret ordinary text immediately, so verify the shell/prompt. Control characters, line separators, and bidi controls are rejected, not rewritten into a different command.

Disable, update, remove, close, either lock mode, detach, and shutdown invalidate running extension authority. Already accepted SSH connections remain ordinary Vyx sessions. Every installed extension can be removed; removal never deletes its saved servers. Runtime failures stop the worker and require explicit Reload; there is no restart loop.

Packages and grants live under `<data-dir>/extensions/`, outside vault synchronization and recovery exports. Publication uses checked local files, atomic replacement, and durability checks. If publication or revocation reports uncertainty, activation stays blocked: use **Retry** to reconcile actual state. An unsaved revocation may not survive restart; a warning is not a rollback or a successful durable save.

### Isolation and limits

SDK packages run in a separate `vyx-extension-worker` executable containing Wasmtime/wasmtime-wasi **49.0.1**. Vyx obtains this native worker only from the official release matching its own version, never from an extension publisher. The worker and verified metadata are cached privately under `<data-dir>/extensions/runtime/`; cached execution works offline, with ownership, permissions, version, protocol, and SHA-256 checked before use. Updating Vyx may require explicitly downloading its matching worker. Cancellation can leave an already published verified cache file, but cannot grant permissions or launch it.

The worker accepts only approved immutable Wasm bytes through pipes. WebAssembly and denied imports provide the sandbox; process separation contains failures. WASI has no preopened filesystem, inherited environment, sockets, DNS, terminal, or subprocess capability. The narrowly scoped native Tailscale adapter described below is a host service, not guest process access.

Each event gets a fresh Wasm store; JavaScript globals are not persistent. Explicit JSON state lasts only while that surface remains open. Limits include 8 MiB Wasm, 64 KiB manifest/state/diagnostic ring, 1 MiB protocol frames, 128 MiB linear memory, a 1 MiB Wasm stack, 100 million fuel units, 32 broker calls per event, a 10-second event deadline including broker waits, and a 20-second compile/start deadline. Queues are bounded; a native watchdog kills and reaps stalled workers. Views support at most 4,096 items, 16 actions, and 24 nonsecret form fields, within the frame limit.

The linear-memory limit is **not** a total process-RSS cap. Compilation/native allocations can still exhaust host memory; the watchdog bounds time, not every system-OOM outcome. This boundary does not protect against a compromised OS, malicious same-user native software, or a Wasmtime sandbox escape.

## Vyx AI

**Vyx AI** (`com.vyx.ai`) is an optional first-party package backed by native provider, chat, storage, and approval code. Install it from the official Extensions release catalog, then review and enable the package. Open the chat with **Ctrl+B, then a**: an empty chat and the first row of the AI **Settings** open the **setup guide**. Its stages—activate the package, turn on Vyx AI and chat, add a provider, choose the default provider, finish the provider's sign-in, key, or model, choose permissions, and **Start chatting**—show as done (✓), current (▸), or pending (·). Enter runs the current stage, and **Providers and advanced settings** reaches every option. Opening the guide sends nothing. **Master AI** starts off, and installation alone never contacts a provider. Core SSH needs neither this package nor an AI account.

The package is an activation and Settings entry, not a credential-handling guest. Only the official package identity/provenance enables the production native integration. For development, choose **Load development package** for the `dev.vyx.ai` build; Vyx remembers the reviewed path and digest, so it stays active across restarts. A changed or missing file blocks AI requests until you review it again, while local AI settings stay reachable. An unrelated package with the same display name cannot access these native services. Vyx AI never grants the Wasm guest network, credentials, chat history, or terminal contents.

### Providers and billing

| Connection | Availability and billing |
| --- | --- |
| OpenAI API | Native API-key profile, Chat Completions or Responses, model discovery and explicit connection testing. API-account billing, not ChatGPT subscription credits. |
| Anthropic API | Native API-key profile using Messages, streaming and model discovery. Anthropic API-account billing. |
| OpenRouter | Native API-key profile, model discovery and reported usage/cost when available. Requests require support for selected parameters and disable upstream fallback. |
| OpenAI-compatible endpoint | Configurable base URL, optional credential, manual/discovered model IDs, Chat Completions or Responses. Remote endpoints require HTTPS; plain HTTP is limited to loopback. The endpoint operator determines billing and supported controls. |
| ChatGPT / Codex subscription | Linux x86_64/aarch64 through the optional Vyx-managed, tool-free Codex helper. Browser/device-code sign-in, account checks, model discovery and streaming use your ChatGPT Codex entitlement and its limits—not API credits. No separate Codex CLI installation, imported CLI account, API-billing fallback, or automatic model substitution. |
| Anthropic subscription | **Unavailable without prior Anthropic approval.** No claude.ai token extraction or imitation of another client. API-key support remains independent. |

Profiles have separate names, credentials, model defaults, streaming and supported output/temperature/reasoning controls. Model-dependent options remain explicit; leave unsupported optional controls unset. Provider failures are surfaced, not retried through another account or endpoint. Switching an existing conversation's provider/model opens a native review of eligible history; the switch itself sends nothing and discards pending attachments. Connection tests and model discovery are explicit requests, never startup probes. Unknown usage, cost, and account limits are not fabricated.

API profiles start with a short native form: a name, the API key (required for OpenAI, Anthropic, and OpenRouter; optional for a compatible endpoint), and a compatible endpoint's base URL. **Save and discover models** stores the profile and makes one model-list request. If listing fails or the endpoint has none, the profile is kept and **Enter model ID manually** finishes it. A failed model discovery, connection test, or sign-in stays listed in the guide with a retry of that same request and **Edit profile** (or the sign-in options) until it succeeds; a complete configuration is never presented as a verified account.

Changing a profile's routing also reviews every affected conversation's eligible history, including a different tenant path on the same host. Consent binds the provider kind, request API style, and full validated URL—not the shortened diagnostic label. Approval revalidates that identity; cancellation or a stale review leaves the saved route unchanged. Reviews display both full endpoint paths and send no request themselves.

Subscription boundaries follow the [Codex app-server protocol](https://developers.openai.com/codex/app-server), the pinned [startup tool policy](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/ext/extension-api/src/tool_policy.rs), and [Anthropic's third-party Agent SDK restriction](https://code.claude.com/docs/en/agent-sdk/overview). An installed Codex client or a paid consumer subscription does not grant Vyx an unrestricted provider API.

**Missing a provider? Open an issue to request support.** [Request a provider](https://github.com/Mondrethos/vyx/issues/new): include the provider name, public API/authentication documentation, and desired capabilities. Never include API keys, tokens, server logs, or credentials. Settings offers an explicit copy of this URL; Vyx does not open or submit an issue automatically.

### ChatGPT subscription setup

From the guide or **Vyx AI settings / Provider profiles / Add provider profile**, choose **ChatGPT subscription (Codex)**; it needs no API key. Choose **Install isolated Codex helper (review)**—the guide offers it as the next step—then **Sign in with ChatGPT — device code** or **— browser**. A blank model reads **Codex default model**, and setup runs no model discovery for subscription profiles. Once the managed helper's metadata is present, the profile shows **Helper installed; checked when used**; the helper itself is verified each time it starts. The native sign-in dialog shows the complete official URL and any device code; **Copy sign-in link** requests the terminal clipboard. Complete sign-in yourself. Device code works without a browser callback to the Vyx machine; browser sign-in needs that callback. Cancel stops the pending login without replacing an existing saved account.

The helper is an optional AI runtime, not part of the core executable or Wasm worker. Core retains the trusted process, account-state and approval bridge. Installation checks matching release checksums and does not sign in, send conversation data, or install system dependencies. Linux requires **bubblewrap**, unprivileged user namespaces and `/dev/shm` tmpfs; other platforms fail closed. A stock `codex` executable is not accepted, and Vyx never searches its home, settings, history, keyring or account.

The helper pins Codex **0.157.1**, commit `36650394c5b38c2990ccf2a3457165ca3e9d9726`, with an unconditional empty tool policy and a text-only RPC allowlist. Every reply uses a fresh ephemeral thread containing only Vyx's prepared conversation. The launcher exposes an empty home/work directory, fixed TLS/DNS inputs and private volatile state—not the vault, host filesystem, agent sockets or real procfs. Hooks, plugins, MCP, ambient configuration, telemetry and shell/patch/hosted tools are disabled. The helper remains trusted native code with shared networking: this is **not** network-egress containment or a sandbox for a malicious helper binary. OS memory/swap policy still applies.

Completed ChatGPT credentials and refreshes are stored only in Vyx's encrypted local AI state, never sync exports or chat messages. Stop, detach or revocation terminates the helper and removes its volatile state. **Sign out of this subscription profile** clears the selected profile locally, even with Master AI off or the helper missing; standalone Codex is untouched. Account checks, model discovery and connection tests require Master AI on and make no inference request. Model/reasoning/streaming controls are supported; Codex does not expose a maximum-output-token control. Vyx still bounds response size and provides Stop.

### Chat and deliberate context

Use **Ctrl+B, then a** to open/close chat and **Ctrl+B, then Tab** to move focus; both are configurable. Drag the ↔ grip on the panel's left border to resize it: the width is saved when you release, and Esc during the drag restores the previous width. Expanded mode is available, and narrow terminals show the chat full-width without a divider. The panel background differs slightly from the terminals in dark and light themes. **Enter** sends, **Alt+Enter / Shift+Enter** inserts a newline, **Ctrl+C** stops, **Ctrl+P** changes this chat's permission, and **Ctrl+K** opens commands. Mouse controls provide the same operations. Focused chat input never goes to SSH.

Commands include new/temporary conversations, local search, rename/delete, templates, message/code copy, Retry, Regenerate, and edit/resend. Regeneration and edits create visible branches rather than rewriting later history. Markdown/code and reported usage appear in the transcript. Copy requests use the terminal's OSC 52 clipboard support, which the terminal may refuse. Provider links are not fetched automatically.

What a chat may read or change on its own is set by its permission (below). Independently, **Capture context and session names** previews one session's visible snapshot, bounded recent output, or nonsecret server metadata. Every capture carries its source session and time and opens an editable preview; **keep each reviewed attachment before Send**. Best-effort redaction is not a guarantee that text contains no secrets. Context limits visibly omit older messages; the handoff template requests a summary only when sent.

Command explanations, troubleshooting, runbooks, script/config review, and templates have independent controls. These are model assistance preferences, not a security boundary: native permissions and reviews remain mandatory regardless of model output.

### Permissions and actions

Each chat has a permission level, shown on its chip:

- **Chat only:** the model sees only what you type and the attachments you keep. Action requests in its replies are listed as not performed; nothing is read or sent to a session.
- **Assist:** Vyx reads sessions in the chat's scope automatically, and every change—typing, keys, opening or closing sessions, renaming, layout—waits for a native review.
- **Full control:** ordinary commands in tracked sessions run without a per-action prompt. Vyx still asks first for input its check flags as high-risk (privilege changes such as `sudo`, destructive filesystem, storage, power/service, package-removal, account, firewall, container, version/database, or security/scheduling commands), for input it cannot classify reliably (shell wrappers, pipes and compound syntax, history or cursor editing), and for closing a session this chat did not open.

**Settings / Permissions** sets **Default for new chats**, **Maximum allowed**, five capabilities (**Share terminal output automatically**, **Run commands and send keys**, **Open and close sessions**, **Manage tabs and layout**, **Draft saved servers (review required)**), and the **Agent step limit** (1–100). In a fresh setup the guide preselects Assist as default and maximum, every capability, and 20 steps; none of it applies until you choose **Apply**. AI state saved by an earlier Vyx version keeps every chat at Chat only until you apply permissions; no earlier switch turns into automatic actions. Raising the maximum to Full control opens one **Allow Full control** review, and cancelling it changes nothing. A chat changes its own level with the chip or **Ctrl+P**, never above the maximum.

A chat acts only in its scope, shown as **Sessions: N**. A new chat starts with the focused session; sessions it opens join the scope; switching tabs changes neither the scope nor a pending review's target. Reviews show the exact text or keys, the session's UUID, label, and address, and the effect. **Approve** covers that one action; there is no approve-all. Vyx tracks what it has typed into a session; after you type there yourself, or the first time it addresses a session whose pending input it cannot know, the next Enter needs review even in Full control. Risk detection is advisory review routing, not a sandbox: a command that looks ordinary can still do damage, so grant Full control only for servers you would administer this way yourself.

One reply starts at most one run. Its actions run one at a time, at most 8 per reply, and results return to the provider as a **Vyx actions** message marked as untrusted data; the run continues until a reply contains no actions. Reads count toward the step limit; at the limit the run ends with **Step limit reached—send a message to continue**. Vyx cannot tell when a command finishes or whether it succeeded: it captures recent output once the terminal has been quiet for 1.5 seconds (60 seconds at most for a command, 10 for typed text or keys) and labels it as output whose completion and exit status are unknown. A timeout reports that the command may still be running and never sends another command. With **Share terminal output automatically** off, commands can still be submitted, but results report only submission status; output shared earlier stays in that chat's history until you start a new chat.

**Stop** (**Ctrl+C** or the panel's Stop control) ends the stream, queued actions, and any wait; while a review is open, its **Cancel** ends the run. Closing the chat panel, starting or switching chats, changing the chat's scope or level, changing permissions or a capability, typing into a session the run is using, locking, detaching, and changing the package or provider profile stop it the same way. Stop sends no interrupt and cannot undo input already submitted; completed results stay in the transcript. Replies that fail, are stopped, finish while the panel is closed (**Finish replies while closed**), or are reopened from history never run their actions. Opening a saved server keeps the normal host-key and credential prompts, and a saved-server draft opens the ordinary editor and saves nothing until you choose Save.

Suggested code blocks in ordinary replies offer **Insert without Enter** and **Run command** from message details, each after a fresh native review of the exact text, immutable session UUID, and destination. **Run is an interactive-terminal submission, not an isolated SSH exec channel:** it sends the reviewed text followed by Enter without clearing existing input. Pending shell text can combine with it and execute a different command; a foreground program may interpret it as input instead. Vyx cannot verify an empty shell prompt; the review says so and labels approval **Send text + Enter**. Cancel and inspect the target prompt yourself if unsure, and do not Run after Insert without removing the inserted text first. Choosing **Connect** for a saved server in the context menu is a separate user action with its own native approval.

### Names and privacy

Tab title suggestions and automatic tab naming are separate, default-off controls. Automatic naming uses an already-requested reply, never continuous terminal monitoring or hidden title requests. Manual names pin the session until explicitly resumed, and a rename action from the chat respects that pin. Accept/reject, pause/resume, restore-original, and server-prefix controls affect only open session labels, never remote hostnames or saved server records.

Retained chats, profiles and API keys are encrypted inside device-local `state.vyx`, outside synchronized vault content and standalone vault exports. Temporary chats are excluded from persistence and discarded when left or closed. Local search, deletion, retention limits, optional explicit plaintext export, and token-budget warnings are available; exports warn about sensitive unencrypted content and never overwrite an existing file. Closing chat stops a reply by default; the optional background-reply setting permits only an already-requested reply to finish. Lock/detach, relevant permission revocation, package replacement, and shutdown cancel authority. Cancellation cannot reverse provider charges or remove information already sent.

Existing local states remain readable and untouched default AI state is omitted. After saving nondefault AI state, older strict local-state readers cannot open that device's file; earlier builds may also reject saved action results or a remembered development path. Do not downgrade that installation. This does not upgrade synchronized vault schema or send AI data to another client. Removing the addon revokes activation but does not silently delete retained native history or profiles; use their explicit deletion controls.

## Tailscale

Install and sign in to Tailscale outside Vyx, with network and SSH policies already administered by the tailnet owner. Download **Tailscale devices** from the official Extensions catalog, then enable it, approving `tailscale.read`, `connections.propose`, and `hosts.propose`. Open **Browse Tailscale devices**. Search is local; **Refresh**, **All**, and **Online** explicitly request fresh status. Device details show available IP/DNS, OS, online/last-seen, tags, and advertised-key metadata. Online status and advertised keys are not policy authorization.

The browser offers two distinct modes:

- **Tailscale SSH:** keyless authentication using only the remote username, port 22, stable tailnet/node identity, and freshly distributed Tailscale host keys. The actual server key must match before SSH `none` authentication. Missing, malformed, or mismatched keys fail without TOFU, a “trust anyway” option, or credential fallback.
- **Standard SSH over Tailscale:** the machine's ordinary SSH service, using a saved credential or a Vyx-owned direct-password draft and a chosen port. Normal SSH authentication and known-host checks apply. An enabled Tailscale SSH server may intercept port 22; choose the intended service explicitly. Failure never silently switches modes.

**Connect once** creates a session without saving a server. **Save server** opens a normal Vyx-owned label/category/authentication draft and performs no connection. Final review is mandatory; matching destinations offer the existing editor rather than overwriting by label. Temporary sessions retain only nonsecret reconnect metadata, not password copies: reconnect (`r` by default in an ended terminal) reopens host-owned confirmation/authentication. Saved sessions reconnect from the current saved record.

For verified keyless SSH check mode, Vyx displays a scrollable server message attributed to the exact node/session. Open HTTPS check links manually in your browser; Vyx never fetches or auto-opens them. Authentication continues without dismissing the notice. Verified notices pause the remaining ordinary 15-second connection/authentication budget, bounded by a separate 30-minute cap. Cancel closes that connection; lock or detach cancels unfinished authentication. Completion, denial, timeout, and cancellation clear the notice and links. Denials retain a bounded, sanitized, URL-redacted reason. Ordinary SSH banners do not gain this behavior.

### Native discovery and routing

**Settings / Tailscale transport** shows the selected executable and accepts an optional absolute CLI override. This Vyx-owned transport setting remains available even without the Tailscale browser package. Otherwise Vyx searches absolute PATH entries; macOS also checks `/usr/local/bin/tailscale` and `/Applications/Tailscale.app/Contents/MacOS/Tailscale`. Discovery validates an executable file and does not run login or policy commands. The setting is local-only. Older strict settings readers cannot load a configured `tailscale_cli_path`; clearing the override removes that field before a settings downgrade.

The adapter invokes only fixed `status --json` and, for Linux userspace networking, `nc <validated-IP> <port>`. Status is bounded to five seconds, 4 MiB stdout, and 16 KiB stderr. Cancellation/overflow/timeouts kill and reap children. Vyx does not run a shell, `sudo`, `tailscale up`, `set`, `login`, `ssh`, account switching, exit-node changes, policy mutations, or remote SSH enablement. Fix missing installation, stopped/unreachable daemon, signed-out state, approval requirements, and unsupported status shapes outside Vyx.

Vyx refreshes destination and local initiating identity before preview and final acceptance. A same-tailnet account switch invalidates a review. Transport uses an advertised Tailscale IPv4 address before IPv6, restricted to `100.64.0.0/10` or `fd7a:115c:a1e0::/48`, never public DNS resolution. Linux `TUN=false` uses the cancellable `nc` transport; Linux kernel networking and macOS use normal TCP. Address-bound standard hosts must match their exact saved IP or full MagicDNS name; short-name guessing and silent Direct fallback are not supported.

Both saved modes preserve `transport: "tailscale"` and continue to use the native adapter even when the browser extension is disabled. Standard SSH retains the canonical reviewed DNS/IP address as its known-host pin namespace, not the resolved dial IP. Keyless SSH uses distributed keys instead and cannot delete an unrelated ordinary pin through **Forget key**.

### Vault compatibility

New vaults use **schema 3**. Valid schema-1 and schema-2 vaults remain readable and are not promoted merely by opening them. Direct credential/password records retain their existing wire shapes and default to Direct routing. The first confirmed Tailscale-routing save upgrades an older synchronized vault to schema 3; Vyx warns first. Cancellation leaves the vault unchanged. **Upgrade every client before saving:** older Vyx clients cannot read a schema-3 vault. Removing Tailscale records does not downgrade it.

Keyless records store the remote username plus stable tailnet/node identity, require Tailscale routing and port 22, and treat the stored hostname as display metadata. Identity is read-only in the editor; choose another node through the reviewed browser. Explicit conversion to standard authentication removes that identity while retaining Tailscale routing unless you separately choose Direct. Export/restore and synchronization retain the route and destination identity; local extension grants never synchronize.

See Tailscale's [SSH documentation](https://tailscale.com/docs/features/tailscale-ssh) and [CLI reference](https://tailscale.com/docs/reference/tailscale-cli) for installation and policy administration.

## Authoring extensions

Authors need **Node 24 LTS** and [Javy **9.1.0**](https://github.com/bytecodealliance/javy/releases/tag/v9.1.0). Official Javy Linux author binaries require glibc 2.35 or newer; that is not an end-user Vyx requirement. Native Windows is outside this release; WSL is the intended Windows route but remains unverified. The SDK pins esbuild 0.25.12 and TypeScript 5.9.3.

Download `vyx-extension-sdk.tgz` from the Vyx release and verify it against that release's `SHA256SUMS`. Registry publication is not required. With the tarball in the current directory:

```sh
SDK="$(pwd)/vyx-extension-sdk.tgz"
npm exec --ignore-scripts --package="$SDK" -- \
  vyx-extension init ./my-extension --id org.example.tools --sdk "$SDK"
cd my-extension
npm install --ignore-scripts
npm run typecheck
npm run build
```

Install `dist/org.example.tools.vyxext` explicitly through Settings, or upload it together with the generated `dist/vyx-extensions.json` to the same published, non-prerelease GitHub Release. Users can add that repository in Extensions; no central marketplace registration is needed. The index includes the full manifest and exact asset name, size, and SHA-256. Vyx verifies these against the downloaded package before offering installation. `vyx-extension pack --project . --out release/custom-name.vyxext` also writes an adjacent index naming that custom asset. Publish the package and index together; publishing neither installs nor enables anything locally.

The generated project is a working async host/session browser with list, detail, form, state, and reviewed-proposal examples. `vyx-extension pack` performs the same validated build/package operation. Unsupported/missing Javy versions fail with an explicit toolchain error; installing an extension never downloads or runs author tools.

Settings registration requires no additional SDK hook or manifest field: Vyx derives the entry from `id`, `name`, and `description` after installation. The ID keeps selection and permission review bound to the same package when the installed list changes. This is a host-owned management page, not automatic execution of `onEvent` or persistent guest configuration storage.

API v1 uses a default-exported `defineExtension({ onEvent })`. Async handlers return `{ view, state?, proposal? }`; `ui.list`, `ui.detail`, and `ui.form` construct plain declarative views. `ctx.hosts.list()`, `ctx.sessions.list()`, and `ctx.tailscale.status()` return permission-checked nonsecret metadata. Omitting `state` preserves previous successful state. Reload/failure/close/lock/detach discard it. Only an actual user command launch, action, or submission can propose; `open` with `reason: "reload"` cannot reuse prior intent.

Builds bundle ES2023 JavaScript, reject unresolved/dynamic imports and Node built-ins, and compile a static WASI-preview-1 core module with Javy stream I/O, text encoding, and promise draining enabled. Pure-JS dependencies must bundle without unsupported APIs. Timers, Node APIs, DOM, arbitrary `fetch`, durable guest storage, secret storage, and generic execution are intentionally absent. Logging is redirected before author code runs to bounded, sanitized in-app diagnostics; source maps stay in `.vyx-build`, outside production packages. AI providers are native-only; the SDK exposes no provider or credential broker.

The pinned build uses `-C deterministic=y -J event-loop=y`; Javy's default plugin already enables stream I/O and text encoding. This avoids randomized configuration-map ordering in Javy 9.1.0 and fixes clocks/randomness during compiler pre-initialization so release packages can be compared byte-for-byte. Guest pre-initialized random state is **not a cryptographic entropy source**; authentication, secrets, opaque references, and approval authority remain native host responsibilities.

For development, run `npm run dev`, then explicitly choose **Load development package** in Vyx. The SDK watches/builds only; it neither launches Vyx nor touches a vault. Vyx debounces immutable replacements, cancels old authority, and offers **Reload**. Optional **Trust rebuilds from this development path** is session-only and bounded to the reviewed path, ID, and permission ceiling; additions or ID changes require fresh review. It does not bypass the sandbox or permit reload proposals.

Approving **Load development package** remembers the reviewed path and digest across restarts: the next start reattaches the same bytes without another review and without changing enablement or grants. Rebuild trust stays session-only, and a changed or missing file needs review again. A development package approved by an earlier Vyx version has no remembered path, so load it once after upgrading. Loading identical installed bytes again reattaches the watcher for the current workspace.

An installed local `dev.vyx.ai` package keeps **Open Vyx AI settings** as the first action on its package page, including after a restart and while disabled; a disabled package is reached from the **Settings / Extensions** list because only enabled packages have their own entry. Local provider configuration remains accessible without activating AI requests. If its file changed or moved, choose **Load development package** on that page, approve the local package, then **Review and enable** if disabled. The load action is also available on the parent Extensions page. Reinstalling or updating identical bytes is a no-op that preserves enablement and grants; it does not substitute for explicit development activation. Vyx shows activation instructions and blocks inference, account requests, context reads and server actions until reviewed. Neither enabling nor opening an inactive native AI identity falls back to downloading or running the sandbox worker. The worker is for SDK guest extensions, not Vyx AI.

First-party sources live in `extensions/tailscale/` and `extensions/ai/`. Both use the same SDK/package format; Tailscale uses the broker and Vyx AI declares native chat/settings entry points:

```sh
npm ci --ignore-scripts
npm run build -w @vyx/extension-sdk
npm run typecheck --workspaces
npm test --workspaces
npm run build -w @vyx/tailscale-extension
npm run dev -w @vyx/tailscale-extension
npm run build -w @vyx/ai-extension
npm run dev -w @vyx/ai-extension
```

Production builds use reserved `com.vyx.tailscale` and `com.vyx.ai`; development scripts override them with unverified `dev.vyx.tailscale` and `dev.vyx.ai`. Generated production packages and their per-package catalogs are committed, never embedded in core. Release CI regenerates and compares both packages, creates one combined release index, packages the SDK tarball, and runs an actual extension-worker round trip with Node/Javy absent from the worker environment on all four Linux-musl/macOS release targets. Static Linux loader checks cover both executables.

Build core and the optional worker separately to keep engine features out of core:

```sh
cargo build -p vyx --locked --release --features extension-worker --bin vyx-extension-worker
cargo build -p vyx --locked --release --no-default-features --bin vyx
cargo test --workspace --locked --features extension-worker
python3 scripts/extension-smoke.py target/release/vyx \
  target/release/vyx-extension-worker extensions/tailscale/dist/com.vyx.tailscale.vyxext
```

Build the optional subscription helper separately; the default route uses rootless Podman (or Docker), not a system Codex installation:

```sh
python3 scripts/build-codex-helper.py
python3 scripts/codex-helper-smoke.py \
  "target/codex-helper/vyx-codex-$(uname -m)-unknown-linux-musl"
```

The recipe verifies the exact upstream commit and patched file hashes, enforces a static executable, and carries the upstream Apache-2.0 LICENSE/NOTICE. `--native` uses a prepared Rust 1.95.0/musl/CMake/Clang toolchain; `--work-dir` and `--output` select build locations. After verification, repeat with `--install-data-dir PATH` to provision only that Vyx directory's optional helper cache. Existing matching managed builds are reused. Linux release jobs also run the account-free, network-isolated helper smoke.

GitHub-backed installation requires the release's `vyx-extensions.json` and indexed package assets. Optional Wasm runtime installation additionally requires the matching official `vyx-extension-worker-<target>` asset and `SHA256SUMS`. Codex installation requires the separate `vyx-codex-<target>`, `vyx-codex-LICENSE`, `vyx-codex-NOTICE` and checksum assets. Older releases lacking these assets produce a missing-asset error; Vyx does not fall back to an untrusted runtime or install system dependencies.

### Verification boundaries

Local verification exercises real Javy/Wasmtime workers, bounded adversarial Wasm, native CLI fixtures, encrypted-vault compatibility, and real SSH/TUI flows against a controlled loopback server, including a delayed verified `none`-authentication notice.

Store verification uses the actual terminal UI, including catalog browsing, disabled installation, permission/runtime consent, cancellation, legacy migration, cache integrity failures, and separate-worker execution. Successful package and runtime downloads are exercised through an isolated HTTPS release fixture with process-local certificate trust; this does not imply the new assets have been uploaded to the public Vyx release. The SDK tarball is also exercised from a separate generated consumer project.

These fixtures do not prove live tailnet policy or browser reauthentication. Authorized two-node Tailscale checks, a real userspace-networked daemon, macOS CLI variants, WSL, and external four-target release jobs require their respective environments and are not claimed from native Linux fixture runs.

AI verification includes native Linux PTY interactions against isolated HTTP/SSH fixtures: disabled/master-off rejection, streamed replies/cancellation, edited attachment review, exact reviewed command bytes, model switching, branching, temporary-history disposal, and pinned manual titles. Encrypted storage and HTTP/SSE regressions run without real provider credentials. These fixtures do not establish live OpenAI/Anthropic/OpenRouter account compatibility, paid quotas, clipboard acceptance by every terminal, or other-platform UI behavior; no real provider login or remote administration is claimed.

Permissions and actions are exercised by a disposable PTY driver (pexpect and pyte, keyboard and SGR mouse input) against a loopback asyncssh server whose sessions are real `/bin/sh` shells and a scripted OpenAI-compatible fixture, including an endpoint without a model list. It covers the setup guide with discovered and manual model IDs and a visible failed discovery with its retry, a ChatGPT subscription profile up to its cancelled helper-install review, Chat only, Assist reviews, Full control consent and its risk, unclassifiable, unknown-input, and close reviews, AI-opened sessions behind the native host-key prompt, renames, layouts, and server drafts, output sharing off, the step limit, quiescence and timeouts, every cancellation path including idle lock and detach, stale approvals after focus changes, a closed target, and a package change, remembered development approval across restarts and changed bytes, and AI state written by a build from before permissions existed. Workspace, Settings, and dialog captures cover 160×48, 100×32, 80×24, and 38×9 in a dark and a light theme with plain and Codicon icons. This run downloaded no Codex helper and used no live provider account, ChatGPT sign-in, or platform other than Linux.

Codex verification additionally exercises the installed native Linux UI, signed-out account checks, reviewed/cached helper installation and local sign-out with Master AI off. A private-network TLS fixture runs the real managed helper through Vyx's native provider client with synthetic credentials: exact streamed text, reported token usage, subscription routing and empty advertised tool lists are checked. Injected shell/patch calls return unsupported-tool results without execution; an ambient-file marker never enters model context. Offline helper probes reject filesystem/configuration/tool RPCs and file inputs. These checks do not establish real ChatGPT OAuth completion or a particular account's subscription entitlement.

## Website

`website/` is the static project site: a landing page with the install command and `screens.html` with five captured product screens. It is plain HTML, CSS, and JavaScript modules with no build step and no external requests; preview it with `python3 -m http.server --directory website`. Instrument Serif and Geist Mono are self-hosted under the SIL Open Font License (`website/assets/fonts/`). `website/assets/js/scenes-data.js` holds the screens, captured from the release build on a demo vault and recolored from base16 default-dark to gruvbox-dark-medium by palette role; it also carries the Codicons outlines (CC BY 4.0) that the screens use.
