use crate::binary::BinaryMeta;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub pass: bool,
    pub details: String,
}

/// Run all 13 Betanet 1.1 §11 compliance checks against a binary
pub fn run_all_checks(meta: &BinaryMeta) -> Vec<CheckResult> {
    vec![
        check_11_1_htx_transport(meta),
        check_11_2_access_tickets(meta),
        check_11_3_noise_xk_handshake(meta),
        check_11_4_http_emulation(meta),
        check_11_5_scion_bridging(meta),
        check_11_6_betanet_transports(meta),
        check_11_7_bootstrap_mechanism(meta),
        check_11_8_mixnode_selection(meta),
        check_11_9_alias_ledger(meta),
        check_11_10_cashu_vouchers(meta),
        check_11_11_governance(meta),
        check_11_12_anticorrelation_fallback(meta),
        check_11_13_slsa_provenance(meta),
    ]
}

/// Write compliance report as JSON
pub fn write_report_json(
    out_path: &PathBuf,
    binary_path: &str,
    results: &[CheckResult],
) -> Result<(), String> {
    let report = serde_json::json!({
        "binary": binary_path,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "total_checks": results.len(),
        "passed_checks": results.iter().filter(|r| r.pass).count(),
        "failed_checks": results.iter().filter(|r| !r.pass).count(),
        "overall_compliance": results.iter().all(|r| r.pass),
        "spec_version": "Betanet 1.1",
        "checks": results
    });

    fs::write(out_path, serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Failed to write report: {e}"))
}

/* -------------------------------------------------------------------- */
/* Betanet 1.1 §11 Compliance Check Implementations                    */
/* -------------------------------------------------------------------- */

/// §11.1: HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH
fn check_11_1_htx_transport(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();
    
    // Check all sources: strings, symbols, sections
    let all_sources: Vec<&str> = meta.strings.iter().map(|s| s.as_str())
        .chain(meta.imported_symbols.iter().map(|s| s.as_str()))
        .chain(meta.exported_symbols.iter().map(|s| s.as_str()))
        .chain(meta.section_names.iter().map(|s| s.as_str()))
        .collect();
    
    // HTX protocol implementation (enhanced detection)
    if all_sources.iter().any(|s| {
        let lower = s.to_lowercase();
        (lower.contains("htx") && (lower.contains("transport") || lower.contains("protocol"))) ||
        lower.contains("cover_transport") ||
        s.contains("htx_")  // Function prefixes
    }) {
        indicators.push("HTX protocol");
    } else {
        missing.push("HTX protocol");
    }
    
    // TCP-443 transport (check for symbols and port usage)
    if all_sources.iter().any(|s| 
        s.contains(":443") || 
        s.contains("TCP_443") ||
        s.contains("bind_443") ||
        s.contains("listen_443")
    ) {
        indicators.push("TCP-443");
    } else {
        missing.push("TCP-443");
    }
    
    // QUIC-443 transport (check for QUIC library symbols)
    if all_sources.iter().any(|s| {
        let lower = s.to_lowercase();
        lower.contains("quic") || 
        s.contains("quic_") ||  // QUIC function calls
        lower.contains("h3_") || // HTTP/3
        meta.dynamic_dependencies.iter().any(|dep| dep.contains("quic"))
    }) {
        indicators.push("QUIC-443");
    } else {
        missing.push("QUIC-443");
    }
    
    // Origin mirroring (check for TLS fingerprinting libraries)
    if all_sources.iter().any(|s| 
        s.contains("JA3") || 
        s.contains("JA4") || 
        (s.contains("origin") && s.contains("mirror")) ||
        s.contains("tls_fingerprint") ||
        s.contains("client_hello")
    ) {
        indicators.push("Origin mirroring");
    } else {
        missing.push("Origin mirroring");
    }
    
    // ECH (Encrypted Client Hello)
    if all_sources.iter().any(|s| 
        s.contains("ECH") || 
        s.contains("encrypted_client_hello") ||
        s.contains("ech_") ||  // ECH function calls
        meta.crypto_components.iter().any(|crypto| crypto.algorithm.contains("ECH"))
    ) {
        indicators.push("ECH support");
    } else {
        missing.push("ECH support");
    }
    
    let pass = missing.len() <= 1; // Allow one missing component for flexibility
    let details = if pass {
        format!("HTX transport implementation found: {}", indicators.join(", "))
    } else {
        format!("Missing HTX transport components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };
    
    CheckResult {
        id: "BN-11.1".to_string(),
        pass,
        details,
    }
}

/// §11.2: Negotiated-carrier, replay-bound access tickets
fn check_11_2_access_tickets(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Access ticket implementation
    if meta.strings.iter().any(|s| s.contains("access") && (s.contains("ticket") || s.contains("Ticket"))) {
        indicators.push("Access tickets");
    } else {
        missing.push("Access tickets");
    }

    // Carrier negotiation (cookie, query, body)
    if meta.strings.iter().any(|s| s.contains("Cookie:") || s.contains("__Host-")) {
        indicators.push("Cookie carrier");
    }

    if meta.strings.iter().any(|s| s.contains("bn1=") || s.contains("query")) {
        indicators.push("Query carrier");
    }

    if meta.strings.iter().any(|s| s.contains("application/x-www-form-urlencoded")) {
        indicators.push("Body carrier");
    }

    if indicators.len() < 2 {
        missing.push("Carrier negotiation");
    }

    // Replay protection
    if meta.strings.iter().any(|s| s.contains("nonce") || s.contains("replay")) {
        indicators.push("Replay protection");
    } else {
        missing.push("Replay protection");
    }

    // X25519 for ticket exchange
    if meta.strings.iter().any(|s| s.contains("X25519") || s.contains("x25519")) {
        indicators.push("X25519 key exchange");
    } else {
        missing.push("X25519 key exchange");
    }

    let pass = missing.is_empty();
    let details = if pass {
        format!("Access ticket system found: {}", indicators.join(", "))
    } else {
        format!("Missing access ticket components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.2".to_string(),
        pass,
        details,
    }
}

/// §11.3: Noise XK with key separation, nonce lifecycle, and rekeying
fn check_11_3_noise_xk_handshake(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Noise XK protocol
    if meta.strings.iter().any(|s| s.contains("Noise") && (s.contains("XK") || s.contains("xk"))) {
        indicators.push("Noise XK");
    } else {
        missing.push("Noise XK");
    }

    // Hybrid X25519-Kyber768 (required from 2027-01-01)
    if meta.strings.iter().any(|s| s.contains("Kyber") || s.contains("kyber")) {
        indicators.push("Kyber768");
    } else {
        missing.push("Kyber768 (PQ)");
    }

    // Key separation
    if meta.strings.iter().any(|s| s.contains("HKDF") && (s.contains("K0c") || s.contains("K0s"))) {
        indicators.push("Key separation");
    } else {
        missing.push("Key separation");
    }

    // Rekeying
    if meta.strings.iter().any(|s| s.contains("KEY_UPDATE") || s.contains("rekey")) {
        indicators.push("Rekeying");
    } else {
        missing.push("Rekeying");
    }

    // Nonce management
    if meta.strings.iter().any(|s| s.contains("nonce") && s.contains("counter")) {
        indicators.push("Nonce lifecycle");
    } else {
        missing.push("Nonce lifecycle");
    }

    let pass = missing.is_empty();
    let details = if pass {
        format!("Noise XK handshake found: {}", indicators.join(", "))
    } else {
        format!("Missing Noise XK components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.3".to_string(),
        pass,
        details,
    }
}

/// §11.4: HTTP/2/3 emulation with adaptive cadences
fn check_11_4_http_emulation(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // HTTP/2 support
    if meta.strings.iter().any(|s| s.contains("h2") || s.contains("HTTP/2") || s.contains("SETTINGS")) {
        indicators.push("HTTP/2");
    } else {
        missing.push("HTTP/2");
    }

    // HTTP/3 support
    if meta.strings.iter().any(|s| s.contains("h3") || s.contains("HTTP/3")) {
        indicators.push("HTTP/3");
    } else {
        missing.push("HTTP/3");
    }

    // PING cadence
    if meta.strings.iter().any(|s| s.contains("PING") && (s.contains("cadence") || s.contains("random"))) {
        indicators.push("PING cadence");
    } else {
        missing.push("PING cadence");
    }

    // PRIORITY frames
    if meta.strings.iter().any(|s| s.contains("PRIORITY")) {
        indicators.push("PRIORITY frames");
    } else {
        missing.push("PRIORITY frames");
    }

    // Idle padding
    if meta.strings.iter().any(|s| s.contains("padding") || s.contains("dummy") && s.contains("DATA")) {
        indicators.push("Idle padding");
    } else {
        missing.push("Idle padding");
    }

    let pass = missing.len() <= 1; // Allow one missing component
    let details = if pass {
        format!("HTTP emulation found: {}", indicators.join(", "))
    } else {
        format!("Missing HTTP emulation components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.4".to_string(),
        pass,
        details,
    }
}

/// §11.5: SCION bridging via HTX tunnels
fn check_11_5_scion_bridging(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // SCION protocol support
    if meta.strings.iter().any(|s| s.contains("SCION") || s.contains("scion")) {
        indicators.push("SCION protocol");
    } else {
        missing.push("SCION protocol");
    }

    // Gateway functionality
    if meta.strings.iter().any(|s| s.contains("gateway") || s.contains("Gateway")) {
        indicators.push("Gateway");
    } else {
        missing.push("Gateway");
    }

    // Transition control stream
    if meta.strings.iter().any(|s| s.contains("Transition") || s.contains("stream_id")) {
        indicators.push("Transition control");
    } else {
        missing.push("Transition control");
    }

    // CBOR encoding
    if meta.strings.iter().any(|s| s.contains("CBOR") || s.contains("cbor")) {
        indicators.push("CBOR encoding");
    } else {
        missing.push("CBOR encoding");
    }

    // No public transition headers
    if !meta.strings.iter().any(|s| s.contains("transition_header") || s.contains("public_wire")) {
        indicators.push("No public headers");
    }

    let pass = missing.len() <= 1;
    let details = if pass {
        format!("SCION bridging found: {}", indicators.join(", "))
    } else {
        format!("Missing SCION bridging components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.5".to_string(),
        pass,
        details,
    }
}

/// §11.6: Betanet transport protocols
fn check_11_6_betanet_transports(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // /betanet/htx/1.1.0
    if meta.strings.iter().any(|s| s.contains("/betanet/htx/1.1.0")) {
        indicators.push("HTX 1.1.0");
    } else {
        missing.push("/betanet/htx/1.1.0");
    }

    // /betanet/htxquic/1.1.0
    if meta.strings.iter().any(|s| s.contains("/betanet/htxquic/1.1.0")) {
        indicators.push("HTXQUIC 1.1.0");
    } else {
        missing.push("/betanet/htxquic/1.1.0");
    }

    // Optional WebRTC
    if meta.strings.iter().any(|s| s.contains("/betanet/webrtc/1.0.0")) {
        indicators.push("WebRTC 1.0.0");
    }

    let pass = missing.is_empty();
    let details = if pass {
        format!("Betanet protocols found: {}", indicators.join(", "))
    } else {
        format!("Missing required betanet protocols: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.6".to_string(),
        pass,
        details,
    }
}

/// §11.7: Bootstrap via rotating rendezvous with PoW
fn check_11_7_bootstrap_mechanism(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Rotating rendezvous DHT
    if meta.strings.iter().any(|s| s.contains("rendezvous") || s.contains("DHT")) {
        indicators.push("Rendezvous DHT");
    } else {
        missing.push("Rendezvous DHT");
    }

    // BeaconSet
    if meta.strings.iter().any(|s| s.contains("BeaconSet") || s.contains("beacon")) {
        indicators.push("BeaconSet");
    } else {
        missing.push("BeaconSet");
    }

    // Proof of Work
    if meta.strings.iter().any(|s| s.contains("proof") && s.contains("work") || s.contains("PoW")) {
        indicators.push("Proof of Work");
    } else {
        missing.push("Proof of Work");
    }

    // mDNS service
    if meta.strings.iter().any(|s| s.contains("_betanet._udp") || s.contains("mDNS")) {
        indicators.push("mDNS service");
    }

    // Bluetooth LE
    if meta.strings.iter().any(|s| s.contains("0xB7A7") || s.contains("Bluetooth")) {
        indicators.push("Bluetooth LE");
    }

    // No deterministic seeds
    if !meta.strings.iter().any(|s| s.contains("deterministic") && s.contains("seed")) {
        indicators.push("No deterministic seeds");
    }

    let pass = missing.len() <= 1;
    let details = if pass {
        format!("Bootstrap mechanism found: {}", indicators.join(", "))
    } else {
        format!("Missing bootstrap components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.7".to_string(),
        pass,
        details,
    }
}

/// §11.8: Mixnode selection with BeaconSet randomness
fn check_11_8_mixnode_selection(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Nym mixnet
    if meta.strings.iter().any(|s| s.contains("Nym") || s.contains("mixnet")) {
        indicators.push("Nym mixnet");
    } else {
        missing.push("Nym mixnet");
    }

    // BeaconSet for randomness
    if meta.strings.iter().any(|s| s.contains("BeaconSet") || s.contains("beacon")) {
        indicators.push("BeaconSet randomness");
    } else {
        missing.push("BeaconSet randomness");
    }

    // Per-stream entropy
    if meta.strings.iter().any(|s| s.contains("streamNonce") || s.contains("stream") && s.contains("entropy")) {
        indicators.push("Per-stream entropy");
    } else {
        missing.push("Per-stream entropy");
    }

    // VRF for hop selection
    if meta.strings.iter().any(|s| s.contains("VRF") || s.contains("verifiable") && s.contains("random")) {
        indicators.push("VRF selection");
    } else {
        missing.push("VRF selection");
    }

    // Path diversity
    if meta.strings.iter().any(|s| s.contains("diversity") || s.contains("distinct") && s.contains("AS")) {
        indicators.push("Path diversity");
    } else {
        missing.push("Path diversity");
    }

    let pass = missing.len() <= 2;
    let details = if pass {
        format!("Mixnode selection found: {}", indicators.join(", "))
    } else {
        format!("Missing mixnode selection components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.8".to_string(),
        pass,
        details,
    }
}

/// §11.9: Alias ledger with finality-bound 2-of-3
fn check_11_9_alias_ledger(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Alias ledger
    if meta.strings.iter().any(|s| s.contains("alias") && (s.contains("ledger") || s.contains("record"))) {
        indicators.push("Alias ledger");
    } else {
        missing.push("Alias ledger");
    }

    // 2-of-3 finality
    if meta.strings.iter().any(|s| s.contains("finality") || s.contains("2-of-3")) {
        indicators.push("2-of-3 finality");
    } else {
        missing.push("2-of-3 finality");
    }

    // Chain support (Handshake, Filecoin, Ethereum L2)
    let mut chains = Vec::new();
    if meta.strings.iter().any(|s| s.contains("Handshake") || s.contains("handshake")) {
        chains.push("Handshake");
    }

    if meta.strings.iter().any(|s| s.contains("Filecoin") || s.contains("FVM")) {
        chains.push("Filecoin");
    }

    if meta.strings.iter().any(|s| s.contains("Ethereum") || s.contains("Raven-Names")) {
        chains.push("Ethereum L2");
    }

    if chains.len() >= 2 {
        indicators.push("Multi-chain support");
    } else {
        missing.push("Multi-chain support");
    }

    // Emergency Advance for liveness
    if meta.strings.iter().any(|s| s.contains("Emergency") && s.contains("Advance")) {
        indicators.push("Emergency Advance");
    } else {
        missing.push("Emergency Advance");
    }

    let pass = missing.len() <= 1;
    let details = if pass {
        format!("Alias ledger found: {} | Chains: {}", indicators.join(", "), chains.join(", "))
    } else {
        format!("Missing alias ledger components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.9".to_string(),
        pass,
        details,
    }
}

/// §11.10: Cashu vouchers with Lightning settlement
fn check_11_10_cashu_vouchers(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Cashu implementation
    if meta.strings.iter().any(|s| s.contains("Cashu") || s.contains("cashu")) {
        indicators.push("Cashu");
    } else {
        missing.push("Cashu");
    }

    // FROST-Ed25519 mints
    if meta.strings.iter().any(|s| s.contains("FROST") && s.contains("Ed25519")) {
        indicators.push("FROST-Ed25519");
    } else {
        missing.push("FROST-Ed25519");
    }

    // 128-byte vouchers
    if meta.strings.iter().any(|s| s.contains("voucher") || s.contains("Voucher")) {
        indicators.push("Vouchers");
    } else {
        missing.push("Vouchers");
    }

    // Lightning settlement
    if meta.strings.iter().any(|s| s.contains("Lightning") || s.contains("lightning")) {
        indicators.push("Lightning");
    } else {
        missing.push("Lightning");
    }

    // Keyset management
    if meta.strings.iter().any(|s| s.contains("keyset") || s.contains("Keyset")) {
        indicators.push("Keyset management");
    } else {
        missing.push("Keyset management");
    }

    let pass = missing.len() <= 2;
    let details = if pass {
        format!("Cashu payment system found: {}", indicators.join(", "))
    } else {
        format!("Missing Cashu components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.10".to_string(),
        pass,
        details,
    }
}

/// §11.11: Governance with anti-concentration caps
fn check_11_11_governance(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // Voting power calculation
    if meta.strings.iter().any(|s| s.contains("vote_weight") || s.contains("voting") && s.contains("power")) {
        indicators.push("Voting power");
    } else {
        missing.push("Voting power");
    }

    // Uptime score
    if meta.strings.iter().any(|s| s.contains("uptime") && s.contains("score")) {
        indicators.push("Uptime scoring");
    } else {
        missing.push("Uptime scoring");
    }

    // Anti-concentration caps
    if meta.strings.iter().any(|s| s.contains("AS") && (s.contains("cap") || s.contains("20%"))) {
        indicators.push("AS caps");
    } else {
        missing.push("AS caps");
    }

    // Quorum requirements
    if meta.strings.iter().any(|s| s.contains("quorum") || s.contains("0.67")) {
        indicators.push("Quorum");
    } else {
        missing.push("Quorum");
    }

    // Partition safety
    if meta.strings.iter().any(|s| s.contains("partition") && s.contains("safety")) {
        indicators.push("Partition safety");
    } else {
        missing.push("Partition safety");
    }

    let pass = missing.len() <= 2;
    let details = if pass {
        format!("Governance system found: {}", indicators.join(", "))
    } else {
        format!("Missing governance components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.11".to_string(),
        pass,
        details,
    }
}

/// §11.12: Anti-correlation fallback with cover connections
fn check_11_12_anticorrelation_fallback(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();

    // UDP to TCP fallback
    if meta.strings.iter().any(|s| s.contains("fallback") && (s.contains("TCP") || s.contains("UDP"))) {
        indicators.push("UDP→TCP fallback");
    } else {
        missing.push("UDP→TCP fallback");
    }

    // Cover connections
    if meta.strings.iter().any(|s| s.contains("cover") && s.contains("connection")) {
        indicators.push("Cover connections");
    } else {
        missing.push("Cover connections");
    }

    // Anti-correlation measures
    if meta.strings.iter().any(|s| s.contains("anti") && s.contains("correlation")) {
        indicators.push("Anti-correlation");
    } else {
        missing.push("Anti-correlation");
    }

    // Randomized timing
    if meta.strings.iter().any(|s| s.contains("random") && (s.contains("delay") || s.contains("timing"))) {
        indicators.push("Randomized timing");
    } else {
        missing.push("Randomized timing");
    }

    // MASQUE CONNECT-UDP
    if meta.strings.iter().any(|s| s.contains("MASQUE") || s.contains("CONNECT-UDP")) {
        indicators.push("MASQUE");
    } else {
        missing.push("MASQUE");
    }

    let pass = missing.len() <= 2;
    let details = if pass {
        format!("Anti-correlation fallback found: {}", indicators.join(", "))
    } else {
        format!("Missing anti-correlation components: {} | Found: {}", 
                missing.join(", "), indicators.join(", "))
    };

    CheckResult {
        id: "BN-11.12".to_string(),
        pass,
        details,
    }
}

/// §11.13: SLSA 3 provenance artifacts for reproducible builds (enhanced)
fn check_11_13_slsa_provenance(meta: &BinaryMeta) -> CheckResult {
    let mut indicators = Vec::new();
    let mut missing = Vec::new();
    
    // SLSA provenance
    if meta.strings.iter().any(|s| s.contains("SLSA") || s.contains("slsa")) {
        indicators.push("SLSA");
    } else {
        missing.push("SLSA");
    }
    
    // Provenance artifacts
    if meta.strings.iter().any(|s| s.contains("provenance") || s.contains("Provenance")) {
        indicators.push("Provenance artifacts");
    } else {
        missing.push("Provenance artifacts");
    }
    
    // Reproducible builds (enhanced detection)
    if meta.build_reproducibility.has_build_id {
        indicators.push("Build ID present");
    } else {
        missing.push("Build ID");
    }
    
    if !meta.build_reproducibility.deterministic_indicators.is_empty() {
        indicators.push("Deterministic build indicators");
    } else {
        missing.push("Deterministic build indicators");
    }
    
    if !meta.build_reproducibility.timestamp_embedded {
        indicators.push("No embedded timestamps");
    } else {
        missing.push("Deterministic timestamps");
    }
    
    // Build attestation (check for signing symbols/sections)
    if meta.strings.iter().any(|s| s.contains("attestation") || s.contains("signature")) ||
       meta.section_names.iter().any(|s| s.contains("signature") || s.contains("sign")) {
        indicators.push("Build attestation");
    } else {
        missing.push("Build attestation");
    }
    
    let pass = missing.len() <= 2; // More lenient for SLSA
    let details = format!("Build reproducibility analysis: {} | Missing: {} | Build ID: {:?}", 
                         indicators.join(", "), 
                         missing.join(", "),
                         meta.build_reproducibility.build_id_type);
    
    CheckResult {
        id: "BN-11.13".to_string(),
        pass,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::collections::HashMap;

    fn create_compliant_test_meta() -> BinaryMeta {
        BinaryMeta {
            path: PathBuf::from("betanet_compliant_binary"),
            format: crate::binary::BinFormat::Elf,
            size_bytes: 10485760,
            strings: vec![
                // §11.1: HTX Transport
                "HTX".to_string(),
                ":443".to_string(),
                "QUIC".to_string(),
                "JA3".to_string(),
                "ECH".to_string(),
                // §11.2: Access Tickets
                "access_ticket".to_string(),
                "Cookie:".to_string(),
                "bn1=".to_string(),
                "nonce".to_string(),
                "X25519".to_string(),
                // §11.3: Noise XK
                "Noise_XK".to_string(),
                "Kyber".to_string(),
                "HKDF".to_string(),
                "KEY_UPDATE".to_string(),
                // §11.6: Betanet transports
                "/betanet/htx/1.1.0".to_string(),
                "/betanet/htxquic/1.1.0".to_string(),
                // §11.13: SLSA
                "SLSA".to_string(),
                "provenance".to_string(),
                "reproducible_build".to_string(),
            ],
            sha256: "a1b2c3d4e5f6".to_string(),
            needed_libs: vec![
                "libquic.so".to_string(),
                "libp2p.so".to_string(),
                "libnoise.so".to_string(),
            ],
            raw: vec![
                0x7f, 0x45, 0x4c, 0x46, // ELF magic
                0x02, 0x01, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, // ET_DYN (PIE)
                0x3e, 0x00, // EM_X86_64
            ],
            embedded_files: vec![],
            compiler_info: Some(crate::binary::CompilerInfo {
                compiler: "rustc".to_string(),
                version: "1.70.0".to_string(),
                optimization_level: "3".to_string(),
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
            }),
            build_environment: crate::binary::BuildEnvironment {
                build_tool: Some("cargo".to_string()),
                build_version: Some("1.70.0".to_string()),
                build_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
                environment_variables: HashMap::new(),
            },
            crypto_components: vec![],
            static_libraries: vec![],
            licenses: vec![],
            betanet_indicators: crate::binary::BetanetIndicators {
                htx_transport: vec![],
                protocol_versions: vec![],
                crypto_protocols: vec![],
                network_transports: vec![],
                p2p_protocols: vec![],
                governance_indicators: vec![],
            },
            build_reproducibility: crate::binary::BuildReproducibility {
                has_build_id: true,
                build_id_type: Some("GNU Build ID".to_string()),
                build_id_value: Some("deadbeef".to_string()),
                deterministic_indicators: vec!["SOURCE_DATE_EPOCH".to_string()],
                timestamp_embedded: false,
            },
            imported_symbols: vec!["quic_connect".to_string(), "htx_transport_new".to_string()],
            exported_symbols: vec!["betanet_init".to_string()],
            section_names: vec![".text".to_string(), ".htx".to_string()],
            dynamic_dependencies: vec!["libquic.so.1".to_string()],
        }
    }

    #[test]
    fn test_compliant_binary_passes_core_checks() {
        let meta = create_compliant_test_meta();
        
        // Test a few key checks
        let htx_result = check_11_1_htx_transport(&meta);
        assert!(htx_result.pass, "HTX transport check failed: {}", htx_result.details);
        
        let transport_result = check_11_6_betanet_transports(&meta);
        assert!(transport_result.pass, "Betanet transport check failed: {}", transport_result.details);
        
        let tickets_result = check_11_2_access_tickets(&meta);
        assert!(tickets_result.pass, "Access tickets check failed: {}", tickets_result.details);
    }

    #[test]
    fn test_all_checks_return_13_results() {
        let meta = create_compliant_test_meta();
        let results = run_all_checks(&meta);

        assert_eq!(results.len(), 13, "Expected exactly 13 Betanet 1.1 compliance checks");
        
        // Verify all check IDs are present
        let expected_ids: Vec<&str> = vec![
            "BN-11.1", "BN-11.2", "BN-11.3", "BN-11.4", "BN-11.5", "BN-11.6",
            "BN-11.7", "BN-11.8", "BN-11.9", "BN-11.10", "BN-11.11", "BN-11.12", "BN-11.13"
        ];
        
        for expected_id in expected_ids {
            assert!(results.iter().any(|r| r.id == expected_id),
                   "Missing check ID: {}", expected_id);
        }
    }
}
