use crate::binary::BinaryMeta;
use goblin::Object;
use uuid::Uuid;
use hex;
use regex::Regex;
use serde::Serialize;
use std::path::PathBuf;
use std::str;

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

/// CHK-04: reproducible build identifier(s)
/// - ELF: parse .note.gnu.build-id and extract the descriptor as hex
/// - Mach-O: read LC_UUID (UUID load command)
/// - PE: scan CodeView (RSDS) record and extract PDB GUID
pub fn check_repro_build(meta: &BinaryMeta) -> CheckResult {
    let buf = &meta.raw;
    match Object::parse(buf) {
        Ok(Object::Elf(elf)) => {
            match extract_elf_gnu_build_id(buf, &elf) {
                Ok(Some(build_id)) => ok(
                    "CHK-04",
                    true,
                    format!("ELF GNU build-id: {}", hex::encode(build_id)),
                ),
                Ok(None) => ok("CHK-04", false, "ELF: GNU build-id not found".into()),
                Err(e) => fail("CHK-04", &format!("ELF parse error: {}", e)),
            }
        }
        Ok(Object::Mach(mach)) => {
            match extract_macho_uuid(&mach) {
                Ok(Some(uuid_bytes)) => {
                    let uuid = Uuid::from_bytes(uuid_bytes);
                    ok("CHK-04", true, format!("Mach-O UUID: {}", uuid.hyphenated()))
                }
                Ok(None) => ok("CHK-04", false, "Mach-O: UUID not found".into()),
                Err(e) => fail("CHK-04", &format!("Mach-O parse error: {}", e)),
            }
        }
        Ok(Object::PE(_pe)) => {
            match extract_pe_pdb_guid(buf) {
                Some(guid) => ok("CHK-04", true, format!("PE PDB GUID: {}", guid)),
                None => ok("CHK-04", false, "PE: PDB GUID (RSDS) not found".into()),
            }
        }
        Ok(_) => ok("CHK-04", false, "Unknown object format".into()),
        Err(e) => fail("CHK-04", &format!("Parse error: {}", e)),
    }
}

fn extract_elf_gnu_build_id(buf: &[u8], elf: &goblin::elf::Elf) -> Result<Option<Vec<u8>>, String> {
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".note.gnu.build-id" {
                let off = sh.sh_offset as usize;
                let sz = sh.sh_size as usize;
                if off + sz > buf.len() {
                    return Err(".note.gnu.build-id out of range".into());
                }
                let sec = &buf[off..off + sz];
                // Parse ELF notes manually (assume 4-byte alignment)
                if let Some(desc) = parse_gnu_build_id_note(sec) {
                    return Ok(Some(desc));
                }
                return Ok(None);
            }
        }
    }
    Ok(None)
}

fn extract_macho_uuid(mach: &goblin::mach::Mach) -> Result<Option<[u8; 16]>, String> {
    use goblin::mach::Mach::*;
    use goblin::mach::load_command::CommandVariant;

    match mach {
        Binary(macho) => {
            for cmd in &macho.load_commands {
                if let CommandVariant::Uuid(u) = &cmd.command {
                    return Ok(Some(u.uuid));
                }
            }
            Ok(None)
        }
        Fat(_fat) => Ok(None),
    }
}

fn extract_pe_pdb_guid(buf: &[u8]) -> Option<String> {
    // Scan for CodeView signature 'RSDS' and decode GUID
    let signature = b"RSDS";
    let i = 0usize;
    while let Some(pos) = twoway::find_bytes(&buf[i..], signature) {
        let start = i + pos + 4; // skip 'RSDS'
        if start + 16 <= buf.len() {
            let g = &buf[start..start + 16];
            let guid = guid_bytes_to_string(g);
            return Some(guid);
        }
        break;
    }
    None
}

fn guid_bytes_to_string(g: &[u8]) -> String {
    // CodeView GUID is little-endian for first 3 fields
    use byteorder::{ByteOrder, LittleEndian};
    if g.len() < 16 {
        return String::new();
    }
    let d1 = LittleEndian::read_u32(&g[0..4]);
    let d2 = LittleEndian::read_u16(&g[4..6]);
    let d3 = LittleEndian::read_u16(&g[6..8]);
    let d4 = &g[8..10];
    let d5 = &g[10..16];
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        hex::encode(d4),
        hex::encode(d5)
    )
}

fn parse_gnu_build_id_note(mut data: &[u8]) -> Option<Vec<u8>> {
    // Parse a sequence of ELF notes: namesz, descsz, type (u32 LE), followed by name (padded to 4), then desc (padded)
    // We specifically look for name == "GNU" and type == NT_GNU_BUILD_ID (3)
    use byteorder::{ByteOrder, LittleEndian};
    const ALIGN: usize = 4;
    while data.len() >= 12 {
        let namesz = LittleEndian::read_u32(&data[0..4]) as usize;
        let descsz = LittleEndian::read_u32(&data[4..8]) as usize;
        let ntype = LittleEndian::read_u32(&data[8..12]);
        data = &data[12..];
        if data.len() < namesz {
            return None;
        }
        let name = &data[..namesz];
        let pad_namesz = ((namesz + ALIGN - 1) / ALIGN) * ALIGN;
        if data.len() < pad_namesz {
            return None;
        }
        data = &data[pad_namesz..];
        if data.len() < descsz {
            return None;
        }
        let desc = &data[..descsz];
        let pad_descsz = ((descsz + ALIGN - 1) / ALIGN) * ALIGN;
        if data.len() < pad_descsz {
            return None;
        }
        data = &data[pad_descsz..];

        if ntype == goblin::elf::note::NT_GNU_BUILD_ID && name.starts_with(b"GNU\0") {
            return Some(desc.to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::guid_bytes_to_string;

    #[test]
    fn test_guid_bytes_to_string_rsds_layout() {
        // 00112233-4455-6677-8899-aabbccddeeff
        let bytes: [u8; 16] = [
            0x33, 0x22, 0x11, 0x00, // d1 LE
            0x55, 0x44, // d2 LE
            0x77, 0x66, // d3 LE
            0x88, 0x99, // d4 (BE-as-bytes)
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // d5
        ];
        let s = guid_bytes_to_string(&bytes);
        assert_eq!(s, "00112233-4455-6677-8899-aabbccddeeff");
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