use anyhow::Result;
use clap::Parser;
use kitty_enc::*;

fn main() -> Result<()> {
    let cli = Cli::parse();
    handle_cli(cli)
}
