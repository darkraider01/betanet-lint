mod binary;
mod checks;

use anyhow::Result; 
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "betanet-lint", version, about = "Betanet spec compliance linter")]

struct Args{
    ///Path to the binary to check
    
    #[arg(long)]
    binary: PathBuf,

    ///Output Json report path
    #[arg(long)]
    report: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    tracing::info!("Running linter on {:?}", args.binary);

    // TODO: parse binary and run checks
    let meta = binary::parse_binary(&args.binary)?;
    let res = checks::check_libp2p(&meta);

    println!("Check {}: {} ({})", res.id, if res.pass { "PASS" } else { "FAIL" }, res.details);


    Ok(())
}