use anyhow::{Context, Result};
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
    about = "Encrypted terminal SSH workspace",
    long_about = "A native terminal workspace for saved SSH connections, reusable credentials, and snippets.\n\nVaults are encrypted on this device. Optional self-hosted synchronization stores only ciphertext. The vault passphrase cannot be recovered by the server. Imported keys and passwords are portable; agent credentials require each device's local SSH agent.\n\nvyx starts or reattaches to one local workspace per data directory. Detaching or closing the attached terminal keeps SSH sessions running in a local background process. The detached workspace stays unlocked and is accessible to your OS account. Quit disconnects all sessions and stops that process; sessions do not survive a reboot or worker exit.",
    after_help = "Keyboard: Ctrl+B then d to detach; Ctrl+B then q to quit; Ctrl+B then ? for help. Reattach with vyx or vyx attach.\nUpdates: vyx update installs the newest verified release. Quiet daily release checks can be disabled with VYX_NO_UPDATE_CHECK=1.\nSync deployment: HTTPS origin with a valid certificate, or a literal loopback HTTP origin over a local tunnel. Never expose the plain HTTP sync server to the Internet."
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "DIR",
        help = "Vault directory (default: platform user data directory/vyx)"
    )]
    data_dir: Option<PathBuf>,
    #[arg(long, hide = true)]
    worker: bool,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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
        return workspace::connect(&data_dir, restore.as_deref(), attach_only).await;
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
        if let Some(store) = startup::acquire(&mut screen, directory.clone(), restore).await? {
            let result = vyx::app::run(&mut screen, store.clone()).await;
            store.drain().await?;
            result?;
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
