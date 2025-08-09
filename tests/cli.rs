use assert_cmd::prelude::*;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn runs_and_writes_report() {
    let dir = tempdir().unwrap();
    let report = dir.path().join("report.json");

    // Use the current binary (cargo run needs a binary arg); point at cargo itself as target
    // On all OS, we can point at this test binary (self), but easier to point at cargo executable path
    let target = std::env::current_exe().unwrap();

    let output = Command::cargo_bin("betanet-lint")
        .unwrap()
        .arg("lint")
        .arg("--binary").arg(target)
        .arg("--report").arg(&report)
        .output()
        .unwrap();

    // Allow exit code 0 (all pass) or 2 (some checks fail)
    let code = output.status.code().unwrap_or(-1);
    assert!([0, 2].contains(&code), "unexpected exit code: {}", code);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Compliance report for:"));
    assert!(std::fs::metadata(&report).is_ok(), "report not written");
}
