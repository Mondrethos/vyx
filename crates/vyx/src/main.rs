use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vyx::{
    screen::{Screen, safe_text},
    startup,
    vault::Directory,
    workspace::{self, Workspace},
};

#[derive(Parser)]
#[command(
    name = "vyx",
    version,
    override_usage = "vyx [OPTIONS] [SERVER]\n       vyx [OPTIONS] <COMMAND>",
    about = "Encrypted terminal SSH workspace",
    long_about = "A native terminal workspace for saved SSH connections, reusable credentials, and snippets.\n\nOne standalone core executable with built-in SSH. Core SSH needs no system ssh, language runtime, helper binary, or sync service. Extensions are optional: Settings > Extensions can download the Vyx-managed sandbox worker and browse extension packages from GitHub Releases, with explicit download and permission review. Installed extensions need no Node.js or author tools. Linux release binaries are statically linked; macOS releases use system libraries.\n\nVaults are encrypted on this device. Optional self-hosted synchronization stores only ciphertext. The vault passphrase cannot be recovered by the server. Imported keys and passwords are portable; agent credentials require each device's local SSH agent.\n\nvyx starts or reattaches to one local workspace per data directory. Only an explicit detach keeps the workspace running in a background process of the same executable. Closing the attached terminal, losing its frontend, or confirming Quit disconnects SSH and stops the workspace. Sessions do not survive a reboot or worker exit. Idle locking also applies while detached; its timeout and session policy are configurable in Settings > Security.",
    after_help = "Start: vyx starts or reattaches to your workspace; vyx NAME connects to a saved server.\nPrefix: Ctrl+B (editable) opens the command bar; press it twice to send Ctrl+B to SSH.\nSettings: Ctrl+B then , or the Settings footer button; Ctrl+B then ? lists every shortcut.\nDetach: Ctrl+B then d leaves the workspace running; reattach with vyx or vyx attach.\nQuit: Ctrl+B then q asks first; closing the terminal also stops Vyx and its SSH sessions.\nUse --help for the full reference.",
    after_long_help = concat!(
        "Command bar: the configured prefix (Ctrl+B by default), Settings, and Shortcuts stay visible in the footer. Press the prefix or click its button to expand a flat bottom bar upward. Commands wrap into rows, show their current keys and layout, and overlay SSH panes without resizing them. Choose by key or click; Esc (default), another click on the prefix, or an outside click collapses the bar. The keys beside Settings and Shortcuts follow the prefix; clicking either icon opens it directly, even over dialogs and menus, except during quit confirmation. Plain mode labels these controls S and ?; Codicons mode uses the shared icon glyphs. Unavailable commands are dimmed. If needed, page using the arrow buttons, wheel, or displayed paging keys. In menus and forms, text input and existing context-specific bindings take precedence over a conflicting custom prefix.\n",
        "Settings: Ctrl+B then , (default) or the Settings footer button opens Workspace, Themes, Security, Keyboard shortcuts, Vault synchronization, Tailscale transport, Setup wizard, and Extensions. At 100 columns and 20 rows or larger, section navigation stays visible beside the actual controls. Up/Down or Tab/Shift+Tab selects a section; Enter focuses its controls. Click a section or a control directly with the mouse. Controls retain their own field, search, and editing bindings. On a page with an unsaved draft (Workspace, Vault synchronization, Tailscale transport, a Security form, or a shortcut being edited), Discard or Esc discards that draft; pages whose actions apply immediately, such as Themes and the shortcut list, just go back. Clicking another section or turning the wheel over the section list keeps drafts while Settings remains open; leaving the Setup wizard discards its progress. Saves remain in the active section. Smaller terminals use a compact section list with drill-in pages; resizing preserves the selected section and current draft. Esc from section navigation or Close closes Settings and discards unsaved drafts. Ctrl+B then ? or the Shortcuts footer button opens the complete, scrollable shortcut reference. Workspace preferences, themes, security preferences, and keyboard bindings persist locally in settings.json beside the vault; they are not synchronized. The sync access token remains encrypted in the vault.\n",
        "Security: Settings > Security > Auto-lock sets an idle timeout (30s, 10m, 1h; 0 disables; maximum 24h). The default is 10 minutes and Disconnect and lock: close SSH sessions, unload the decrypted vault, and discard unsaved forms. Keep sessions running instead hides the workspace behind a passphrase prompt while retaining SSH sessions and the decrypted vault in process memory. Keyboard, paste, and mouse actions reset the timer; SSH output does not. Explicitly detached workspaces also lock. Unlock requires the vault passphrase. Change vault passphrase is available only when synchronization is not configured, requires the current passphrase, and accepts a new passphrase of at least 16 characters. It preserves vault contents and live SSH sessions; existing encrypted exports and backups still need their original passphrase.\n",
        "Quitting: Ctrl+B then q shows a confirmation, including the live SSH session count. Enter confirms; Esc returns to the previous screen without discarding its draft. Closing the terminal window or losing the frontend also stops the workspace and SSH sessions, but Vyx cannot display a reliable warning after its terminal disappears. Enable close confirmation in your terminal emulator if needed. Use Ctrl+B then d only when intentionally leaving the workspace running. Remote programs may stop on disconnect unless they run in a remote multiplexer.\n",
        "Themes: Settings > Themes offers the bundled Tinted collection: 565 Base16, Base24, and Tinted8 themes, split into Dark (428) and Light (137). Browse with arrows, paging keys, mouse wheel, or scrollbar. Click Search or press Tab (default) to filter by name or ID; Enter/Tab keeps the filter, Esc undoes it, and Ctrl+U clears it. Browsing previews a palette without changing the active theme. Apply activates and saves it immediately across the UI, startup screens, and SSH default/ANSI colors, without reconnecting or resizing sessions. Explicit SSH RGB and indexed colors 16–255 are preserved. Collection: https://tinted-theming.github.io/tinted-gallery/\n",
        "Sidebar: shared icons distinguish Sessions, Servers, Credentials, Tools, and Sync in both expanded and compact views. Icons use theme-aware colors independently of labels: green sessions, blue servers, gold credentials/folders, purple tools/snippets, and cyan sync. Rows are contiguous with two-cell hierarchy indentation and fixed disclosure/icon slots; resizing does not add blank section rows. Unselected section headings have no filled bars; the selected row has a marker and contrasting background. The Search control at the top opens the metadata filter. Drag the right-hand divider to resize, or click [<]/[>] to collapse into a compact navigation rail and expand again. Preferred width (20–80 columns) and collapsed state are remembered. Narrow terminals use the rail with an expanded sidebar overlay; shrinking the terminal does not overwrite your preferred width.\n",
        "Icons: Settings > Workspace > Icons offers Plain (default, portable ASCII markers) and Codicons. For rich icons, install a Nerd Font containing Codicons from https://www.nerdfonts.com/ and select it as your terminal font, or install Microsoft's Codicons font from https://github.com/microsoft/vscode-codicons and configure it as a terminal fallback/symbol font. Codicons is icon-only: keep your normal monospace text font, and do not select Codicons as your sole text font. For kitty, an example after installing the codicon font family is: symbol_map U+EA60-U+ECFF codicon. Other terminals differ in fallback support and configuration. Restart or refresh your terminal's font discovery as needed, choose Codicons in Workspace settings, and Save workspace. Vyx ships no font assets, downloads no icons, and never installs fonts or changes your terminal configuration. If glyphs are missing or misaligned, configure a compatible font or choose Plain. Save workspace persists icon_mode (plain or nerd_font; existing values unchanged) transactionally with the other workspace preferences. Existing settings without icon_mode use Plain. Codicons by Microsoft: https://github.com/microsoft/vscode-codicons (artwork CC BY 4.0, https://creativecommons.org/licenses/by/4.0/; code MIT). Vyx uses the glyphs provided by the user's terminal font.\n",
        "Terminal layouts: Settings > Workspace > Terminal layout offers Single, Side by side, Stacked, and Grid. Quick-switch with Ctrl+B then l (editable), Layout in the command bar, or the Layout button on the tab strip. Each advances through the four layouts and saves immediately; clicking a tab only focuses that session. These arrange open SSH sessions without reconnecting them; four sessions form a 2x2 Grid. Click a pane or its title to focus it, or use Ctrl+B then n/p by default. Keyboard input and paste go only to the focused session. Each pane has its own SSH terminal size. On small screens, tabs and next/previous session expose additional pages without moving panes when focus changes within a page. The layout preference is saved locally.\n",
        "Terminal resizing: drag the internal borders marked ↔ or ↕ to resize adjacent panes. SSH terminal sizes update live; release saves and Esc cancels the drag. Grid dividers adjust shared columns or rows. Proportions persist locally per layout, including across restarts, and scale with the terminal window. Minimum sizes keep panes usable. Saved proportions apply when the row/column count matches; different split counts start balanced without erasing the saved sizes.\n",
        "Keyboard shortcuts: Up/Down or Tab/Shift+Tab selects an action; PageUp/PageDown and Home/End navigate the list. Enter or e opens the selected reference entry for editing; Esc goes back. In the editor, Ctrl+U clears, Enter saves, and Esc cancels. Edits take effect after Save. Conflicting bindings are rejected. Reset restores the selected action's default; Reset all first asks for confirmation and shows how many customized bindings change. Back returns to the settings sections without discarding an underlying workspace dialog or search.\n",
        "Default keys (editable): Ctrl+B then l cycles terminal layouts; Ctrl+B then d explicitly detaches; Ctrl+B then q confirms quit; Ctrl+B then ? opens Shortcuts; Ctrl+B then , opens Settings. Ctrl+B twice sends the literal prefix to SSH. Reattach with vyx or vyx attach. Ordinary terminal input still goes to SSH.\n",
        "Binding syntax: comma-separated keys, for example Ctrl+G, Up, k. Use Shift+K for uppercase, Comma and Plus for those literal keys, and named keys such as Enter or F3. Mouse controls do not depend on keyboard bindings.\n",
        "Default catalog keys: Up/Down or k/j selects, Left/Right collapses or expands, Enter opens, and a/e adds or edits. / searches metadata as you type; Enter/Tab keeps the filter; Esc restores the previous filter and selection; Ctrl+U clears the query. Outside search, Esc clears a kept filter. i previews a server without interrupting a session.\n",
        "Forms: Tab/Shift+Tab or Down/Up changes fields; Left/Right edits text or changes a choice; Space toggles a checkbox; Enter submits and Esc cancels. Home/End, Backspace, Delete, and Ctrl+U edit text. Mouse users can click a field, a choice, a checkbox, or [<]/[>]; the wheel changes only the focused choice under the pointer and otherwise moves between fields. An invalid value keeps every draft and focuses the first field to fix.\n",
        "Paths: an imported private-key path may start with ~/ for your home folder. Recovery-file paths must be absolute; ~ is not expanded there.\n",
        "Server authentication: in Add/Edit server, choose Saved credential to reuse an entry managed under Credentials, or Password to enter this server's own username and password. Save commits only the chosen method; Cancel discards changes. Server passwords are encrypted in the vault and optional synced snapshots, never in settings.json. Shared credentials are not modified. Changes apply on the next connection; existing SSH sessions stay open with their original login. Password mode also works with no saved credentials. Update all syncing clients before using server-specific passwords (vault schema 2); existing credential-backed vaults remain readable without conversion.\n",
        "Updates: vyx update installs the newest verified release. Quit the old workspace when ready to end its SSH sessions, then restart to load updated UI code; this update changes the local workspace protocol, so an older worker must exit before the new binary can attach. Quiet daily release checks can be disabled with VYX_NO_UPDATE_CHECK=1.\n",
        "Sync deployment: HTTPS origin with a valid certificate, or a literal loopback HTTP origin over a local tunnel. Never expose the plain HTTP sync server to the Internet.\n",
        "\nBundled Tinted schemes — MIT license:\n",
        include_str!("../theme-data/LICENSE.tinted-schemes"),
    )
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        help = "Data directory for the vault and local settings (default: platform user data directory/vyx)"
    )]
    data_dir: Option<PathBuf>,
    #[arg(long, hide = true)]
    worker: bool,
    #[arg(
        value_name = "SERVER",
        conflicts_with = "worker",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        help = "Connect to a saved server by its exact, case-sensitive label",
        long_help = "Connect to a saved server by its exact, case-sensitive label. Missing or duplicate labels show a connection error rather than choosing a destination.\n\nExamples: vyx rpnation; vyx \"Production EU\"; vyx -- update (a server named update, not the update command).\n\nUnlocks the vault when needed and reuses a live session for that saved server. Detach any currently attached terminal first. Restored forms, searches and shortcut menus are preserved; close them to continue the requested connection."
    )]
    server: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Reattach to a running local workspace without starting a new one.
    Attach,
    /// Download, verify, and atomically install the newest stable release.
    Update,
    /// Restore a standalone encrypted snapshot into an empty data directory.
    Restore {
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
    },
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(run());
    // A canceled startup KDF must not keep the process alive after terminal loss.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.server.is_none() || cli.command.is_none(),
        "A saved-server name cannot be combined with a subcommand; use 'vyx -- NAME' for a name that matches a command"
    );
    let (restore, attach_only) = match cli.command {
        None => (None, false),
        Some(Command::Update) => return vyx::update::install_latest().await,
        Some(Command::Attach) => (None, true),
        Some(Command::Restore { file }) => (Some(file), false),
    };
    let data_dir = match cli.data_dir {
        Some(path) => path,
        None => directories::BaseDirs::new()
            .context("Cannot resolve the user data directory; pass --data-dir")?
            .data_dir()
            .join("vyx"),
    };
    if !cli.worker {
        return workspace::connect(&data_dir, restore.as_deref(), attach_only, cli.server.as_deref()).await;
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = Directory::open(data_dir)?;
    anyhow::ensure!(
        !(restore.is_some() && directory.exists()),
        "Restore refuses to overwrite an existing state.vyx"
    );
    let workspace = Workspace::bind(directory.path())?;
    let mut screen = Screen::open(workspace)?;
    let result: Result<()> = async {
        while !screen.is_attached() {
            if screen.next_event().await?.is_none() {
                return Ok(());
            }
        }
        let settings = vyx::settings::Settings::load(directory.path())?;
        if let Some(outcome) = startup::acquire(
            &mut screen, directory.clone(), restore, &settings.bindings, &settings.theme.palette,
            settings.workspace.motion,
        ).await? {
            vyx::app::run(&mut screen, outcome.store, settings, directory.clone(), outcome.recovered, outcome.setup_created).await?;
        }
        Ok(())
    }
    .await;
    let finish = screen
        .finish(
            result
                .as_ref()
                .err()
                .map(|error| safe_text(&format!("{error:#}"))),
        )
        .await;
    result?;
    finish
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_names_and_management_commands_are_unambiguous() {
        let named = Cli::try_parse_from(["vyx", "Production EU", "--data-dir", "vault"]).unwrap();
        assert_eq!(named.server.as_deref(), Some("Production EU"));
        assert_eq!(named.data_dir, Some(PathBuf::from("vault")));
        assert!(named.command.is_none());

        let literal = Cli::try_parse_from(["vyx", "--", "update"]).unwrap();
        assert_eq!(literal.server.as_deref(), Some("update"));
        assert!(literal.command.is_none());

        let update = Cli::try_parse_from(["vyx", "--data-dir", "vault", "update"]).unwrap();
        assert!(matches!(update.command, Some(Command::Update)));
        assert!(update.server.is_none());

        let restore = Cli::try_parse_from([
            "vyx", "--worker", "--data-dir", "vault", "restore", "--file", "backup.vyx",
        ]).unwrap();
        assert!(restore.worker);
        assert!(matches!(restore.command, Some(Command::Restore { file }) if file == PathBuf::from("backup.vyx")));
    }

    #[test]
    fn direct_connections_reject_extra_names_and_worker_arguments() {
        for args in [
            ["vyx", "first", "second"],
            ["vyx", "--worker", "rpnation"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        assert!(Cli::try_parse_from(["vyx", ""]).is_err());
    }
}
