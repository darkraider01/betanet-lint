use clap::{Parser, Subcommand};
use prettytable::{row, Table};
use std::path::PathBuf;

mod binary;
mod checks;
mod sbom;

use binary::BinaryMeta;
use checks::{run_all_checks, write_report_json};

#[derive(Debug, Subcommand)]
enum Command {
    /// Run compliance checks on a binary
    Lint(LintArgs),
    /// Run the integrated test suite
    Test,
}

#[derive(Parser, Debug)]
struct LintArgs {
    /// Path to binary
    #[arg(long)]
    binary: String,

    /// Path to compliance report JSON
    #[arg(long)]
    report: String,

    /// Optional: Path to SBOM JSON
    #[arg(long)]
    sbom: Option<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Betanet §11 compliance linter", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Lint(args) => {
            log::info!("Starting betanet-lint on '{}'", args.binary);

            // Extract binary metadata
            let meta = match BinaryMeta::from_path(args.binary.clone().into()) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Failed to read binary: {}", e);
                    std::process::exit(1);
                }
            };

            println!("\nCompliance report for: {}\n", args.binary);

            // Run compliance checks
            let results = run_all_checks(&meta);

            // Pretty table output
            let mut table = Table::new();
            table.add_row(row!["Check ID", "Status", "Details"]);
            for r in &results {
                table.add_row(row![r.id, if r.pass { "PASS" } else { "FAIL" }, r.details]);
            }
            table.printstd();

            // Write compliance report JSON
            let report_path = PathBuf::from(&args.report);
            if let Err(e) = write_report_json(&report_path, &args.binary, &results) {
                eprintln!("Failed to write report: {}", e);
            } else {
                println!("Wrote report to {}", report_path.display());
            }

            // If SBOM requested, write SBOM JSON
            if let Some(sbom_path) = args.sbom {
                let sbom_path = PathBuf::from(sbom_path);
                match sbom::write_sbom_json(&sbom_path, &meta) {
                    Ok(_) => println!("Wrote SBOM to {}", sbom_path.display()),
                    Err(e) => eprintln!("Failed to write SBOM: {}", e),
                }
            }

            // Exit non-zero if any check failed
            if results.iter().any(|r| !r.pass) {
                std::process::exit(2);
            }
        }
        Command::Test => {
            println!("Running integrated tests...");
            let status = std::process::Command::new("cargo")
                .arg("test")
                .status()
                .expect("Failed to execute cargo test");

            if !status.success() {
                eprintln!("Integrated tests failed.");
                std::process::exit(1);
            }
        } else {
                println!("Integrated tests passed.");
            }
        }
    }
}