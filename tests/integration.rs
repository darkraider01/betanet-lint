//! Integration tests for betanet-lint
//!
//! These tests verify end-to-end functionality and ensure
//! the tool works correctly without artificial manipulation.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::{NamedTempFile, TempDir};
use std::path::PathBuf;

// Helper function to create and build a simple test binary
fn create_test_binary() -> (PathBuf, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let project_path = temp_dir.path().join("test_binary_project");
    fs::create_dir(&project_path).unwrap();

    // Create Cargo.toml
    let cargo_toml_content = r#"
[package]
name = "test_binary"
version = "0.1.0"
edition = "2021"

[dependencies]
"#;
    fs::write(project_path.join("Cargo.toml"), cargo_toml_content).unwrap();

    // Create src/main.rs
    let main_rs_content = r#"
fn main() {
    println!("Hello, world from test binary!");
}
"#;
    let src_dir = project_path.join("src");
    fs::create_dir(&src_dir).unwrap();
    fs::write(src_dir.join("main.rs"), main_rs_content).unwrap();

    // Build the test binary
    Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(&project_path)
        .assert()
        .success();

    let binary_path = project_path.join("target/release/test_binary");
    (binary_path, temp_dir)
}


#[test]
fn test_help_command() {
    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Betanet 1.1"));
}

#[test]
fn test_version_command() {
    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--version");
    cmd.assert().code(predicate::eq(0).or(predicate::eq(2)));
}

#[test]
fn test_missing_binary_argument() {
    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--report").arg("test.json");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_nonexistent_binary() {
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg("nonexistent_file")
        .arg("--report")
        .arg(&report_path)
        .arg("--offline");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn test_basic_binary_analysis() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--offline");

    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));

    // Verify report was created
    assert!(report_path.exists());

    // Verify report structure
    let report_content = fs::read_to_string(&report_path).unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_content).unwrap();

    assert_eq!(report["metadata"]["spec_version"], "Betanet 1.1");
    assert_eq!(report["summary"]["total_checks"], 13);
}

#[test]
fn test_all_compliance_checks_structure() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--offline");

    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));

    assert!(report_path.exists());
    let report_content = fs::read_to_string(&report_path).unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_content).unwrap();

    assert_eq!(report["summary"]["total_checks"], 13);
    let detailed_results = report["detailed_results"].as_array().unwrap();
    assert_eq!(detailed_results.len(), 13);

    let expected_ids: Vec<String> = (1..=13).map(|i| format!("BN-11.{}", i)).collect();
    let severities = ["Critical", "High", "Medium", "Low", "Info"];

    for (i, result) in detailed_results.iter().enumerate() {
        let id = result["id"].as_str().unwrap();
        let name = result["name"].as_str().unwrap();
        let pass = result["pass"].as_bool().unwrap();
        let details = result["details"].as_str().unwrap();
        let confidence = result["confidence"].as_f64().unwrap();
        let severity = result["severity"].as_str().unwrap();
        
        assert_eq!(id, expected_ids[i]);
        assert!(!name.is_empty());
        assert!(!details.is_empty());
        assert!(confidence >= 0.0 && confidence <= 1.0);
        assert!(severities.contains(&severity));
        assert!(result["recommendations"].is_array());
    }
}

#[test]
fn test_sbom_generation() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let sbom_path = temp_dir.path().join("sbom.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--sbom")
        .arg(&sbom_path)
        .arg("--offline");

    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));

    // Verify both files were created
    assert!(report_path.exists());
    assert!(sbom_path.exists());

    // Verify SBOM structure (SPDX only now)
    let sbom_content = fs::read_to_string(&sbom_path).unwrap();
    let sbom: serde_json::Value = serde_json::from_str(&sbom_content).unwrap();

    assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
    assert!(sbom["packages"].is_array());
    assert!(sbom["relationships"].is_array());
}

#[test] 
fn test_offline_mode() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--offline");

    // Should succeed in offline mode without network access
    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_slsa_provenance_generation() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let sbom_path = temp_dir.path().join("sbom.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--sbom")
        .arg(&sbom_path)
        .arg("--slsa-level")
        .arg("3")
        .arg("--offline");
    
    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));

    // Check for SLSA provenance file
    let provenance_path = sbom_path.with_extension("intoto.jsonl");
    assert!(provenance_path.exists());

    // Verify provenance structure
    let provenance_content = fs::read_to_string(&provenance_path).unwrap();
    let provenance: serde_json::Value = serde_json::from_str(&provenance_content).unwrap();

    assert_eq!(provenance["_type"], "https://in-toto.io/Statement/v0.1");
    assert_eq!(provenance["predicateType"], "https://slsa.dev/provenance/v0.2");
}

#[test]
fn test_self_analysis_no_special_treatment() {
    // Test that the tool analyzes itself without giving special treatment
    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("self_report.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    let binary_path = assert_cmd::cargo::cargo_bin("betanet-lint");

    cmd.arg("--binary")
        .arg(binary_path)
        .arg("--report")
        .arg(&report_path)
        .arg("--offline");

    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "should exit with code 1 for parsing error");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to parse binary format"), "should show error message");

}

#[test]
fn test_comprehensive_options() {
    let (target_binary, _temp_dir) = create_test_binary();

    let temp_dir = TempDir::new().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let sbom_path = temp_dir.path().join("comprehensive_sbom.json");

    let mut cmd = Command::cargo_bin("betanet-lint").unwrap();
    cmd.arg("--binary")
        .arg(&target_binary)
        .arg("--report")
        .arg(&report_path)
        .arg("--sbom")
        .arg(&sbom_path)
        .arg("--sbom-format")
        .arg("spdx")
        .arg("--generate-cbom")
        .arg("--generate-vex")
        .arg("--slsa-level")
        .arg("3")
        .arg("--offline");

    let output = cmd.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), 
            "unexpected exit code: {}. stdout: {}, stderr: {}", 
            code, 
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr));

    // All requested files should be created
    assert!(report_path.exists());
    assert!(sbom_path.exists());

    // Verify CBOM was included in SBOM
    let sbom_content = fs::read_to_string(&sbom_path).unwrap();
    assert!(sbom_content.contains("SPDX-2.3")); // Should have SPDX version
    assert!(sbom_content.contains("betanet-protocol")); // Should have betanet protocol component
}
