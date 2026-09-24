mod auth;
mod http;
mod store;

use std::{
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "vyx-server",
    version,
    about = "Opaque encrypted vault sync service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a data directory and print its access token once.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Replace the owner access token without changing the stored vault.
    RotateToken {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Serve the opaque vault HTTP API.
    Serve {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { data_dir } => {
            let token = auth::initialize(&data_dir)?;
            print_token(&token)?;
        }
        Command::RotateToken { data_dir } => {
            let token = auth::rotate(&data_dir)?;
            print_token(&token)?;
        }
        Command::Serve { data_dir, listen } => serve(data_dir, listen).await?,
    }
    Ok(())
}

fn print_token(token: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{token}").context("writing access token to stdout")?;
    output.flush().context("flushing access token to stdout")
}

async fn serve(data_dir: PathBuf, listen: SocketAddr) -> Result<()> {
    let store = store::ServerStore::open(&data_dir)?;
    let state = http::AppState::new(store);
    let application = http::router(state.clone());
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding HTTP listener at {listen}"))?;

    axum::serve(listener, application)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?;
    state.drain_commits().await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
