use clap::Parser;
use prettytable::{row, Table};
use std::path::PathBuf;
use betanet_lint::{binary::BinaryMeta, checks::{run_all_checks, write_report_json}, sbom::{write_sbom_with_options, SbomFormat, SbomOptions, LicenseScanDepth}};

#[derive(Parser, Debug)]
#[command(author, version, about = "Betanet §11 compliance linter with enhanced SBOM", long_about = None)]
struct Cli {
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

    /// Include vulnerability data in SBOM
    #[arg(long)]
    include_vulns: bool,

    /// Generate CBOM (Cryptographic BOM)
    #[arg(long)]
    generate_cbom: bool,

    /// License scanning depth: basic, comprehensive, deep
    #[arg(long, default_value = "basic")]
    license_scan: String,

    /// Generate VEX statements
    #[arg(long)]
    generate_vex: bool,

    /// SLSA provenance level (1-4)
    #[arg(long, default_value = "1")]
    slsa_level: u8,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Starting betanet-lint on '{}'", cli.binary);

    // Extract binary metadata - NO ARTIFICIAL MANIPULATION
    let meta = match BinaryMeta::from_path(cli.binary.clone().into()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read binary: {e}");
            std::process::exit(1);
        }
    };

    println!("\nAnalyzing binary: {}", cli.binary);
    println!("  Format: {:?}", meta.format);
    println!("  Size: {} bytes", meta.size_bytes);
    println!("  Dependencies: {} libraries", meta.needed_libs.len());
    println!("  Crypto components: {}", meta.crypto_components.len());
    println!("  Licenses detected: {}", meta.licenses.len());
    println!("  Static libraries: {}", meta.static_libraries.len());
    println!("  Imported symbols: {}", meta.imported_symbols.len());
    println!("  Exported symbols: {}", meta.exported_symbols.len());
    println!();

    // Run compliance checks - NO SYNTHETIC DATA INJECTION
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
        eprintln!("Failed to write report: {e}");
    } else {
        println!("Wrote report to {}", report_path.display());
    }

    // Generate enhanced SBOM if requested
    if let Some(sbom_path) = cli.sbom {
        let format = if cli.sbom_format.eq_ignore_ascii_case("spdx") {
            SbomFormat::Spdx
        } else {
            SbomFormat::CycloneDx
        };

        let license_scan_depth = match cli.license_scan.as_str() {
            "comprehensive" => LicenseScanDepth::Comprehensive,
            "deep" => LicenseScanDepth::Deep,
            _ => LicenseScanDepth::Basic,
        };

        let options = SbomOptions {
            include_vulnerabilities: cli.include_vulns,
            generate_cbom: cli.generate_cbom,
            license_scan_depth,
            generate_vex: cli.generate_vex,
            slsa_level: cli.slsa_level.clamp(1, 4),
            include_provenance: true,
        };

        match write_sbom_with_options(&PathBuf::from(&sbom_path), &meta, format, options) {
            Ok(_) => {
                println!("Wrote enhanced {} SBOM to {}", cli.sbom_format.to_uppercase(), sbom_path);
                if cli.include_vulns {
                    println!("  ✓ Included vulnerability data");
                }
                if cli.generate_cbom {
                    println!("  ✓ Generated Cryptographic BOM");
                }
                if cli.generate_vex {
                    println!("  ✓ Generated VEX statements");
                }
            }
            Err(e) => eprintln!("Failed to write SBOM: {e}"),
        }
    }

    // Summary
    let passed = results.iter().filter(|r| r.pass).count();
    let total = results.len();
    println!("\n=== SUMMARY ===");
    println!("Compliance: {passed}/{total} checks passed");

    if meta.crypto_components.is_empty() {
        println!("⚠️  No cryptographic components detected");
    } else {
        println!("🔒 {} cryptographic components found", meta.crypto_components.len());
    }

    if meta.licenses.is_empty() {
        println!("⚠️  No license information detected");
    } else {
        println!("📄 {} license(s) detected", meta.licenses.len());
    }

    if meta.build_reproducibility.has_build_id {
        println!("🔨 Build ID detected: {:?}", meta.build_reproducibility.build_id_type);
    }

    // Exit non-zero if any check failed
    if results.iter().any(|r| !r.pass) {
        std::process::exit(2);
    }
}
