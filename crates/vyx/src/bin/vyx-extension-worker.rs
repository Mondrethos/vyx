use anyhow::{Result, bail};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (None, None) => vyx::extensions::worker::worker_main(),
        (Some(flag), None) if flag == "--version" => {
            println!("vyx-extension-worker {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => bail!("Extension worker accepts only private pipe bootstrap, or --version"),
    }
}
