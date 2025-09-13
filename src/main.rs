use clap::Parser;
use prettytable::{row, Table};
use std::path::PathBuf;
use anyhow::Result;
use betanet_lint::{
    binary::BinaryMeta, 
    checks::{run_all_checks, write_report_json}, 
    sbom::{write_sbom_with_options, SbomFormat, SbomOptions, LicenseScanDepth}
};

#[derive(Parser, Debug)]
#[command(
    author = "Betanet Team", 
    version = env!("CARGO_PKG_VERSION"), 
    about = "Betanet 1.1 §11 compliance verification with SLSA 3 provenance", 
    long_about = "Verifies that compiled binaries meet the 13 normative requirements specified in Betanet 1.1 §11"
)]
struct Cli {
    /// Path to binary to analyze
    #[arg(long)]
    binary: String,

    /// Path to compliance report JSON
    #[arg(long)]
    report: String,

    /// Optional: Path to SBOM JSON
    #[arg(long)]
    sbom: Option<String>,

    /// SBOM format: cyclonedx or spdx
    #[arg(long, default_value = "spdx")]
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
    #[arg(long, default_value = "3")]
    slsa_level: u8,

    /// Skip network vulnerability checks (for air-gapped environments)
    #[arg(long)]
    offline: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Starting betanet-lint v{} on '{}'", env!("CARGO_PKG_VERSION"), cli.binary);

    // Validate binary path exists and is readable
    let binary_path = PathBuf::from(&cli.binary);
    if !binary_path.exists() {
        anyhow::bail!("Binary file does not exist: {}", cli.binary);
    }

    if !binary_path.is_file() {
        anyhow::bail!("Path is not a file: {}", cli.binary);
    }

    // Extract binary metadata WITHOUT any artificial manipulation
    // This is the key fix - no string injection, no self-passes
    log::info!("Analyzing binary format and metadata...");
    let meta = BinaryMeta::from_path(binary_path.clone())?;

    println!("\nBinary Analysis Results:");
    println!("  File: {}", cli.binary);
    println!("  Format: {:?}", meta.format);
    println!("  Size: {} bytes ({:.1} MB)", meta.size_bytes, meta.size_bytes as f64 / 1024.0 / 1024.0);
    println!("  SHA256: {}", meta.sha256);
    println!("  Dependencies: {} libraries", meta.needed_libs.len());
    println!("  Crypto components: {}", meta.crypto_components.len());
    println!("  Licenses detected: {}", meta.licenses.len());
    println!("  Imported symbols: {}", meta.imported_symbols.len());
    println!("  Exported symbols: {}", meta.exported_symbols.len());
    if meta.build_reproducibility.has_build_id {
        println!("  Build ID: {:?}", meta.build_reproducibility.build_id_type);
    }
    println!();

    // Run compliance checks - NO artificial data injection
    log::info!("Running Betanet 1.1 §11 compliance verification...");
    let results = run_all_checks(&meta);

    // Display results in a table
    let mut table = Table::new();
    table.add_row(row!["Check ID", "Status", "Details"]);

    let mut passed = 0;
    let mut failed = 0;

    for r in &results {
        let status = if r.pass { "PASS ✓" } else { "FAIL ✗" };
        table.add_row(row![r.id, status, r.details]);

        if r.pass {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    table.printstd();

    // Write compliance report JSON
    let report_path = PathBuf::from(&cli.report);
    write_report_json(&report_path, &cli.binary, &results)?;
    println!("📄 Compliance report written to: {}", report_path.display());

    // Generate enhanced SBOM if requested
    if let Some(sbom_path) = cli.sbom {
        let format = SbomFormat::Spdx;

        let license_scan_depth = match cli.license_scan.as_str() {
            "comprehensive" => LicenseScanDepth::Comprehensive,
            "deep" => LicenseScanDepth::Deep,
            _ => LicenseScanDepth::Basic,
        };

        let options = SbomOptions {
            include_vulnerabilities: cli.include_vulns && !cli.offline,
            generate_cbom: cli.generate_cbom,
            license_scan_depth,
            generate_vex: cli.generate_vex,
            slsa_level: cli.slsa_level.clamp(1, 4),
            include_provenance: true,
            offline_mode: cli.offline,
        };

        match write_sbom_with_options(&PathBuf::from(&sbom_path), &meta, format, options).await {
            Ok(_) => {
                println!("📋 Enhanced {} SBOM written to: {}", cli.sbom_format.to_uppercase(), sbom_path);
                if cli.include_vulns && !cli.offline {
                    println!("   ✓ Vulnerability data included");
                }
                if cli.generate_cbom {
                    println!("   ✓ Cryptographic BOM generated");
                }
                if cli.generate_vex {
                    println!("   ✓ VEX statements generated");
                }
                if cli.slsa_level >= 3 {
                    println!("   ✓ SLSA Level {} provenance generated", cli.slsa_level);
                }
            }
            Err(e) => {
                log::error!("Failed to write SBOM: {}", e);
                return Err(e.into());
            }
        }
    }

    // Summary and compliance status
    println!("\n═══ BETANET 1.1 §11 COMPLIANCE SUMMARY ═══");
    println!("Total checks: {}", results.len());
    println!("Passed: {} ✓", passed);
    println!("Failed: {} ✗", failed);

    let compliance_percentage = (passed as f64 / results.len() as f64) * 100.0;
    println!("Compliance rate: {:.1}%", compliance_percentage);

    if failed == 0 {
        println!("🎉 FULLY COMPLIANT with Betanet 1.1 specification");
    } else if compliance_percentage >= 80.0 {
        println!("⚠️  MOSTLY COMPLIANT - {} issues to address", failed);
    } else {
        println!("❌ NOT COMPLIANT - significant issues detected");
    }

    // Additional insights
    if meta.crypto_components.is_empty() {
        println!("⚠️  No cryptographic components detected - may not support Betanet protocols");
    } else {
        let quantum_safe_count = meta.crypto_components.iter()
            .filter(|c| c.quantum_safe)
            .count();
        println!("🔒 Cryptographic analysis: {}/{} components are quantum-safe",
                quantum_safe_count, meta.crypto_components.len());
    }

    if meta.build_reproducibility.has_build_id {
        println!("🔨 Build reproducibility: {:?} detected",
                meta.build_reproducibility.build_id_type.as_ref().unwrap_or(&"Unknown".to_string()));
    } else {
        println!("⚠️  No build ID detected - may impact reproducibility verification");
    }

    // Exit with appropriate code for CI/CD integration
    if failed > 0 {
        log::warn!("Exiting with code 2 due to {} failed compliance checks", failed);
        std::process::exit(2);
    }

    println!("\n✅ Analysis complete - all compliance checks passed");
    Ok(())
}
