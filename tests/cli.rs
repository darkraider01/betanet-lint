use assert_cmd::prelude::*;
use std::process::Command;
use tempfile::tempdir;
use serde_json;

#[test]
fn test_cli_basic_functionality() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    
    // Use the current test binary as the target for analysis
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .output()
        .unwrap();
    
    // Allow exit code 0 (all pass) or 2 (some checks fail) - both are valid
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analyzing binary:"), "stdout should contain 'Analyzing binary:'");
    assert!(stdout.contains("Wrote report to"), "stdout should contain 'Wrote report to'");
    assert!(stdout.contains("=== SUMMARY ==="), "stdout should contain summary section");
    
    // Verify report file was created
    assert!(std::fs::metadata(&report).is_ok(), "report file should be created");
}

#[test]
fn test_cli_with_sbom_generation() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    let sbom = dir.path().join("sbom.json");
    
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .arg("--sbom").arg(&sbom)
        .arg("--sbom-format").arg("cyclonedx")
        .output()
        .unwrap();
    
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Wrote enhanced CYCLONEDX SBOM"), "should mention SBOM generation");
    
    // Verify both files were created
    assert!(std::fs::metadata(&report).is_ok(), "report file should exist");
    assert!(std::fs::metadata(&sbom).is_ok(), "SBOM file should exist");
}

#[test]
fn test_cli_enhanced_sbom_features() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    let sbom = dir.path().join("enhanced_sbom.json");
    
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .arg("--sbom").arg(&sbom)
        .arg("--generate-cbom")
        .arg("--license-scan").arg("comprehensive")
        .arg("--slsa-level").arg("3")
        .output()
        .unwrap();
    
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generated Cryptographic BOM") || stdout.contains("Cryptographic components"), 
            "should mention CBOM generation");
    
    // Verify SBOM file exists
    assert!(std::fs::metadata(&sbom).is_ok(), "enhanced SBOM file should exist");
    
    // For SLSA level 3, should generate provenance file
    let provenance = sbom.with_extension("intoto.jsonl");
    if std::fs::metadata(&provenance).is_ok() {
        println!("✓ SLSA provenance file generated: {}", provenance.display());
    }
}

#[test]
fn test_cli_spdx_format() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    let sbom = dir.path().join("sbom_spdx.json");
    
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .arg("--sbom").arg(&sbom)
        .arg("--sbom-format").arg("spdx")
        .output()
        .unwrap();
    
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Wrote enhanced SPDX SBOM"), "should mention SPDX SBOM generation");
    
    assert!(std::fs::metadata(&sbom).is_ok(), "SPDX SBOM file should exist");
}

#[test]
fn test_report_content_validation() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .output()
        .unwrap();
    
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    
    // Read and validate report JSON structure
    let report_content = std::fs::read_to_string(&report).expect("should read report file");
    let report_json: serde_json::Value = serde_json::from_str(&report_content)
        .expect("report should be valid JSON");
    
    // Validate required fields
    assert!(report_json.get("binary").is_some(), "report should have binary field");
    assert!(report_json.get("timestamp").is_some(), "report should have timestamp field");
    assert!(report_json.get("total_checks").is_some(), "report should have total_checks field");
    assert!(report_json.get("passed_checks").is_some(), "report should have passed_checks field");
    assert!(report_json.get("failed_checks").is_some(), "report should have failed_checks field");
    assert!(report_json.get("overall_compliance").is_some(), "report should have overall_compliance field");
    assert!(report_json.get("checks").is_some(), "report should have checks array");
    
    // Validate Betanet 1.1 specific fields
    if let Some(spec_version) = report_json.get("spec_version") {
        assert_eq!(spec_version.as_str().unwrap(), "Betanet 1.1", "should specify Betanet 1.1");
    }
    
    // Validate check count
    let total_checks = report_json.get("total_checks").unwrap().as_u64().unwrap();
    assert_eq!(total_checks, 13, "should have exactly 13 Betanet 1.1 compliance checks");
    
    // Validate check structure
    let checks = report_json.get("checks").unwrap().as_array().unwrap();
    assert_eq!(checks.len(), 13, "checks array should have 13 entries");
    
    for (i, check) in checks.iter().enumerate() {
        let expected_id = format!("BN-11.{}", i + 1);
        assert_eq!(check.get("id").unwrap().as_str().unwrap(), expected_id, 
                   "check {} should have correct ID", i);
        assert!(check.get("pass").is_some(), "check should have pass field");
        assert!(check.get("details").is_some(), "check should have details field");
        
        let details = check.get("details").unwrap().as_str().unwrap();
        assert!(!details.is_empty(), "check details should not be empty");
        assert!(!details.contains("[PLACEHOLDER]"), "check should not be placeholder");
    }
}

#[test]
fn test_cli_error_handling() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    
    // Test with non-existent binary
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg("/nonexistent/binary")
        .arg("--report").arg(&report)
        .output()
        .unwrap();
    
    assert_eq!(output.status.code().unwrap(), 1, "should exit with code 1 for file not found");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to read binary"), "should show error message");
}

#[test]
fn test_cli_help() {
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    
    assert_eq!(output.status.code().unwrap(), 0, "help should exit with code 0");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Betanet §11 compliance linter"), "help should mention Betanet compliance");
    assert!(stdout.contains("--binary"), "help should show binary option");
    assert!(stdout.contains("--report"), "help should show report option");
    assert!(stdout.contains("--sbom"), "help should show SBOM option");
    assert!(stdout.contains("--generate-cbom"), "help should show CBOM option");
    assert!(stdout.contains("--slsa-level"), "help should show SLSA level option");
}

#[test]
fn test_vulnerability_scanning_flag() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");
    let sbom = dir.path().join("sbom_with_vulns.json");
    
    let target = std::env::current_exe().unwrap();
    
    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .arg("--sbom").arg(&sbom)
        .arg("--include-vulns")
        .output()
        .unwrap();
    
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Included vulnerability data") {
        println!("✓ Vulnerability scanning was enabled and executed");
    }
}
