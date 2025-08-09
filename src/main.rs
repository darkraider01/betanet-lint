use clap::Parser;
use prettytable::{row, Table};
use std::path::PathBuf;

mod binary;
mod checks;
mod sbom;

use binary::BinaryMeta;
use checks::{run_all_checks, write_report_json};

#[derive(Parser, Debug)]
#[command(author, version, about = "Betanet §11 compliance linter", long_about = None)]
struct Cli {
    /// Compatibility: allow a legacy `lint` positional subcommand
    #[arg(hide = true)]
    command_compat: Option<String>,
    /// Path to binary
    #[arg(long)]
    binary: String,

    /// Path to compliance report JSON
    #[arg(long)]
    report: String,

    /// Optional: Path to SBOM JSON
    #[arg(long)]
    sbom: Option<String>,
    
    /// SBOM format: cyclonedx or spdx
    #[arg(long, default_value = "cyclonedx")]
    sbom_format: String,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Starting betanet-lint on '{}'", cli.binary);

    // Extract binary metadata
    let meta = match BinaryMeta::from_path(cli.binary.clone().into()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read binary: {}", e);
            std::process::exit(1);
        }
    };

    println!("\nAnalyzing binary: {}", cli.binary);
    println!("  Format: {:?}", meta.format);
    println!("  Size: {} bytes\n", meta.size_bytes);

    println!("\nCompliance report for: {}\n", cli.binary);

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
    let report_path = PathBuf::from(&cli.report);
    if let Err(e) = write_report_json(&report_path, &cli.binary, &results) {
        eprintln!("Failed to write report: {}", e);
    } else {
        println!("Wrote report to {}", report_path.display());
    }

    // If SBOM requested, write SBOM JSON
    if let Some(sbom_path) = cli.sbom {
        use sbom::{write_sbom, SbomFormat};
        let format = if cli.sbom_format.eq_ignore_ascii_case("spdx") {
            SbomFormat::Spdx
        } else {
            SbomFormat::CycloneDx
        };
        
        match write_sbom(&PathBuf::from(&sbom_path), &meta, format) {
            Ok(_) => println!("Wrote {} SBOM to {}", cli.sbom_format.to_uppercase(), sbom_path),
            Err(e) => eprintln!("Failed to write SBOM: {}", e),
        }
    }

    // Exit non-zero if any check failed
    if results.iter().any(|r| !r.pass) {
        std::process::exit(2);
    }
}
