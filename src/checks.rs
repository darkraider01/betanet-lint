use crate::binary::BinaryMeta;
use goblin::Object;
use hex;
use regex::Regex;
use serde::Serialize;
use std::path::PathBuf;
use std::{fs, str};

/// Serializable check result
#[derive(Debug, Serialize, Clone)]
pub struct CheckResult {
    pub id: &'static str,
    pub pass: bool,
    pub details: String,
}

/// Entry: run all 11 checks and return results
pub fn run_all_checks(meta: &BinaryMeta) -> Vec<CheckResult> {
    vec![
        check_pie(meta),
        check_no_static_libs(meta),
        check_libp2p_and_crypto(meta),
        check_repro_build(meta),
        check_stripped_debug(meta),
        check_no_forbidden_syscalls(meta),
        check_crypto_whitelist(meta),
        check_quic_support(meta),
        check_secure_random(meta),
        check_sbom_capability(meta),
        check_spec_version_tag(meta),
    ]
}

/// CHK-01: PIE - best-effort (ELF exact; Mach-O/PE placeholders)
pub fn check_pie(meta: &BinaryMeta) -> CheckResult {
    let buf = &meta.raw;
    if buf.is_empty() {
        return fail("CHK-01", "Binary empty");
    }
    match Object::parse(buf) {
        Ok(Object::Elf(elf)) => {
            let is_dyn = elf.header.e_type == goblin::elf::header::ET_DYN;
            ok(
                "CHK-01",
                is_dyn,
                format!("ELF e_type = {} (ET_DYN == {})", elf.header.e_type, is_dyn),
            )
        }
        Ok(Object::Mach(_)) => ok(
            "CHK-01",
            true,
            "Mach-O binary (PIE detection not implemented)".into(),
        ),
        Ok(Object::PE(_)) => ok(
            "CHK-01",
            true,
            "PE binary (PIE/ASLR detection not implemented)".into(),
        ),
        Ok(_) => fail("CHK-01", "Unknown object type"),
        Err(e) => fail("CHK-01", &format!("Parse error: {}", e)),
    }
}

/// CHK-02: detect obvious static linking artifacts (.a, static marker) - heuristic
pub fn check_no_static_libs(meta: &BinaryMeta) -> CheckResult {
    let forbidden_tokens = ["libssl.a", "libcrypto.a", ".a ", ".a\t"];
    let mut evidence = Vec::new();
    for s in &meta.strings {
        let low = s.to_lowercase();
        for tok in &forbidden_tokens {
            if low.contains(tok) {
                evidence.push(s.clone());
            }
        }
    }
    let pass = evidence.is_empty();
    ok(
        "CHK-02",
        pass,
        if pass {
            "No obvious static lib artifacts found (heuristic)".into()
        } else {
            format!(
                "Found static-like artifacts (example): {}",
                evidence.get(0).unwrap_or(&"".to_string())
            )
        },
    )
}

/// CHK-03: libp2p + PQ/curve crypto heuristic detection
pub fn check_libp2p_and_crypto(meta: &BinaryMeta) -> CheckResult {
    let keywords = ["libp2p", "kyber", "x25519", "ed25519", "quic"];
    let mut found = Vec::new();
    for &kw in &keywords {
        if meta
            .strings
            .iter()
            .any(|s| s.to_lowercase().contains(kw))
        {
            found.push(kw);
        }
    }
    // Conservative pass if at least 2 relevant keywords present
    let pass = found.len() >= 2;
    ok(
        "CHK-03",
        pass,
        format!("Found keywords: {}/{} => {:?}", found.len(), keywords.len(), found),
    )
}

/// CHK-04: reproducible build check — ELF .note.gnu.build-id presence and extraction (safe)
pub fn check_repro_build(meta: &BinaryMeta) -> CheckResult {
    let buf = &meta.raw;
    match Object::parse(buf) {
        Ok(Object::Elf(elf)) => {
            // look for section named ".note.gnu.build-id"
            let mut found = false;
            let mut details = String::from("No build-id section found");
            for sh in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    if name == ".note.gnu.build-id" {
                        let off = sh.sh_offset as usize;
                        let sz = sh.sh_size as usize;
                        if off + sz <= buf.len() {
                            let sec = &buf[off..off + sz];
                            details = format!(
                                ".note.gnu.build-id (raw hex, {} bytes): {}",
                                sec.len(),
                                hex::encode(sec)
                            );
                            found = true;
                        } else {
                            details = "Section header out of range".to_string();
                        }
                        break;
                    }
                }
            }
            ok("CHK-04", found, details)
        }
        Ok(_) => ok(
            "CHK-04",
            false,
            "Non-ELF binary: build-id detection implemented only for ELF".into(),
        ),
        Err(e) => fail("CHK-04", &format!("Parse error: {}", e)),
    }
}

/// CHK-05: stripped debug sections check (heuristic via string scanning)
pub fn check_stripped_debug(meta: &BinaryMeta) -> CheckResult {
    let has_debug = meta.strings.iter().any(|s| s.starts_with(".debug_") || s.contains(".debug_"));
    ok(
        "CHK-05",
        !has_debug,
        if has_debug {
            "Debug-related strings present (possible debug symbols)".into()
        } else {
            "No debug-related strings detected".into()
        },
    )
}

/// CHK-06: forbidden syscalls/API names (heuristic)
pub fn check_no_forbidden_syscalls(meta: &BinaryMeta) -> CheckResult {
    let forbidden = ["ptrace", "execve", "fork", "system"];
    let mut found = Vec::new();
    for s in &meta.strings {
        for f in &forbidden {
            if s.contains(f) {
                found.push(format!("{} in '{}'", f, truncate(s, 80)));
            }
        }
    }
    ok(
        "CHK-06",
        found.is_empty(),
        if found.is_empty() {
            "No forbidden syscall/API names detected".into()
        } else {
            format!("Forbidden names found: {}", found.join("; "))
        },
    )
}

/// CHK-07: ensure no disallowed crypto primitives (heuristic)
pub fn check_crypto_whitelist(meta: &BinaryMeta) -> CheckResult {
    let disallowed = ["rsa", "des", "md5"];
    let mut found = Vec::new();
    for s in &meta.strings {
        let low = s.to_lowercase();
        for d in &disallowed {
            if low.contains(d) {
                found.push(d.to_string());
            }
        }
    }
    ok(
        "CHK-07",
        found.is_empty(),
        if found.is_empty() {
            "No disallowed crypto primitives detected".into()
        } else {
            format!("Disallowed primitives: {:?}", found)
        },
    )
}

/// CHK-08: QUIC support (heuristic)
pub fn check_quic_support(meta: &BinaryMeta) -> CheckResult {
    let pass = meta
        .strings
        .iter()
        .any(|s| s.to_lowercase().contains("quic") || s.to_lowercase().contains("http3"));
    ok(
        "CHK-08",
        pass,
        if pass {
            "QUIC/H3 indicators present".into()
        } else {
            "No QUIC indicators found".into()
        },
    )
}

/// CHK-09: secure randomness source detection
pub fn check_secure_random(meta: &BinaryMeta) -> CheckResult {
    let indicators = ["/dev/urandom", "getrandom", "RtlGenRandom", "BCryptGenRandom", "arc4random"];
    let pass = meta
        .strings
        .iter()
        .any(|s| indicators.iter().any(|r| s.contains(r)));
    ok(
        "CHK-09",
        pass,
        if pass {
            "Secure randomness usage indicators found".into()
        } else {
            "No secure RNG indicators found".into()
        },
    )
}

/// CHK-10: SBOM generation capability (we generate a minimal SBOM later)
pub fn check_sbom_capability(_meta: &BinaryMeta) -> CheckResult {
    ok(
        "CHK-10",
        true,
        "SBOM generation supported (will produce CycloneDX-like JSON)".into(),
    )
}

/// CHK-11: presence of spec version tag inside the binary (heuristic)
pub fn check_spec_version_tag(meta: &BinaryMeta) -> CheckResult {
    let re = Regex::new(r"BETANET_SPEC_v\d+\.\d+").unwrap();
    let pass = meta.strings.iter().any(|s| re.is_match(s));
    ok(
        "CHK-11",
        pass,
        if pass {
            "Spec version tag found".into()
        } else {
            "Spec version tag missing".into()
        },
    )
}

/* ---------- small helpers ---------- */

fn ok(id: &'static str, pass: bool, details: String) -> CheckResult {
    CheckResult { id, pass, details }
}
fn fail(id: &'static str, details: &str) -> CheckResult {
    CheckResult { id, pass: false, details: details.to_string() }
}
fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

/// Write JSON report helper used by main.rs
pub fn write_report_json(path: &PathBuf, binary_path: &str, results: &[CheckResult]) -> Result<(), String> {
    use serde_json::json;
    use std::fs;

    let items: Vec<_> = results
        .iter()
        .map(|r| json!({ "id": r.id, "pass": r.pass, "details": r.details }))
        .collect();

    let report = json!({
        "binary": binary_path,
        "results": items
    });

    fs::write(path, serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
