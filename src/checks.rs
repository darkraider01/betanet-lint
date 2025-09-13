//! Betanet 1.1 §11 Compliance Verification
//!
//! This module implements the 13 normative compliance checks specified in
//! Betanet 1.1 Section 11. Each check verifies specific protocol behaviors
//! and implementation requirements, not generic binary hygiene.

use crate::binary::BinaryMeta;
use crate::protocol::{ProtocolAnalyzer, ProtocolSupport};
use crate::crypto::CryptoAnalyzer;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckResult {
    pub id: String,
    pub name: String,
    pub pass: bool,
    pub details: String,
    pub confidence: f32,
    pub severity: Severity,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl CheckResult {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            pass: false,
            details: String::new(),
            confidence: 0.0,
            severity: Severity::Medium,
            recommendations: Vec::new(),
        }
    }

    pub fn pass_with_details(mut self, details: &str, confidence: f32) -> Self {
        self.pass = true;
        self.details = details.to_string();
        self.confidence = confidence;
        self.severity = Severity::Info;
        self
    }

    pub fn fail_with_details(mut self, details: &str, confidence: f32, severity: Severity) -> Self {
        self.pass = false;
        self.details = details.to_string();
        self.confidence = confidence;
        self.severity = severity;
        self
    }

    pub fn add_recommendation(&mut self, recommendation: &str) {
        self.recommendations.push(recommendation.to_string());
    }
}

/// Run all 13 Betanet 1.1 §11 compliance checks against a binary
/// 
/// Each check verifies specific protocol implementation requirements
/// rather than generic binary characteristics.
pub fn run_all_checks(meta: &BinaryMeta) -> Vec<CheckResult> {
    log::info!("Running {} Betanet 1.1 §11 compliance checks", 13);

    let protocol_analyzer = ProtocolAnalyzer::new(meta);
    let crypto_analyzer = CryptoAnalyzer::new(meta);

    let results = vec![
        check_11_1_htx_transport(&protocol_analyzer),
        check_11_2_access_tickets(&protocol_analyzer),
        check_11_3_noise_xk_handshake(&protocol_analyzer, &crypto_analyzer),
        check_11_4_http_emulation(&protocol_analyzer),
        check_11_5_scion_bridging(&protocol_analyzer),
        check_11_6_betanet_transports(&protocol_analyzer),
        check_11_7_bootstrap_mechanism(&protocol_analyzer),
        check_11_8_mixnode_selection(&protocol_analyzer),
        check_11_9_alias_ledger(&protocol_analyzer),
        check_11_10_cashu_vouchers(&protocol_analyzer, &crypto_analyzer),
        check_11_11_governance(&protocol_analyzer),
        check_11_12_anticorrelation_fallback(&protocol_analyzer),
        check_11_13_slsa_provenance(meta),
    ];

    for result in &results {
        log::debug!("Check Result: ID={}, Pass={}, Details={}", result.id, result.pass, result.details);
    }
    results
}

/// Write compliance report as JSON with enhanced metadata
pub fn write_report_json(
    out_path: &PathBuf,
    binary_path: &str,
    results: &[CheckResult],
) -> Result<()> {
    let passed_count = results.iter().filter(|r| r.pass).count();
    let failed_count = results.iter().filter(|r| !r.pass).count();
    let overall_compliance = results.iter().all(|r| r.pass);

    // Analyze failure severity
    let critical_failures = results.iter()
        .filter(|r| !r.pass && matches!(r.severity, Severity::Critical))
        .count();
    let high_failures = results.iter()
        .filter(|r| !r.pass && matches!(r.severity, Severity::High))
        .count();

    let report = serde_json::json!({
        "metadata": {
            "tool": "betanet-lint",
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "spec_version": "Betanet 1.1",
            "spec_section": "§11 Normative Requirements",
            "analysis_target": binary_path
        },
        "summary": {
            "total_checks": results.len(),
            "passed_checks": passed_count,
            "failed_checks": failed_count,
            "compliance_rate": (passed_count as f64 / results.len() as f64) * 100.0,
            "overall_compliance": overall_compliance,
            "critical_failures": critical_failures,
            "high_severity_failures": high_failures
        },
        "compliance_matrix": {
            "transport_layer": check_compliance_category(results, &["BN-11.1", "BN-11.4", "BN-11.5", "BN-11.6"]),
            "cryptography": check_compliance_category(results, &["BN-11.2", "BN-11.3", "BN-11.10"]),
            "network_protocols": check_compliance_category(results, &["BN-11.7", "BN-11.8", "BN-11.12"]),
            "governance_ledger": check_compliance_category(results, &["BN-11.9", "BN-11.11"]),
            "build_integrity": check_compliance_category(results, &["BN-11.13"])
        },
        "detailed_results": results,
        "recommendations": generate_recommendations(results),
        "next_steps": generate_next_steps(results)
    });

    fs::write(out_path, serde_json::to_string_pretty(&report)?)
        .map_err(|e| anyhow::anyhow!("Failed to write report: {}", e))?;

    log::info!("Compliance report written to: {}", out_path.display());
    Ok(())
}

fn check_compliance_category(results: &[CheckResult], check_ids: &[&str]) -> serde_json::Value {
    let category_results: Vec<_> = results.iter()
        .filter(|r| check_ids.contains(&r.id.as_str()))
        .collect();

    let passed = category_results.iter().filter(|r| r.pass).count();
    let total = category_results.len();

    serde_json::json!({
        "passed": passed,
        "total": total,
        "compliance_rate": if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 },
        "status": if passed == total { "COMPLIANT" } else { "NON_COMPLIANT" }
    })
}

fn generate_recommendations(results: &[CheckResult]) -> Vec<String> {
    let mut recommendations = Vec::new();

    for result in results {
        if !result.pass {
            recommendations.extend(result.recommendations.iter().cloned());

            // Add specific recommendations based on check type
            match result.id.as_str() {
                "BN-11.1" => recommendations.push("Implement HTX transport layer with proper TLS+ECH support".to_string()),
                "BN-11.3" => recommendations.push("Upgrade to Noise XK with post-quantum Kyber768 hybrid key exchange".to_string()),
                "BN-11.6" => recommendations.push("Add support for /betanet/htx/1.1.0 and /betanet/htxquic/1.1.0 protocols".to_string()),
                "BN-11.13" => recommendations.push("Implement reproducible builds with SLSA Level 3 provenance attestation".to_string()),
                _ => {}
            }
        }
    }

    recommendations.into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect()
}

fn generate_next_steps(results: &[CheckResult]) -> Vec<String> {
    let failed_checks: Vec<_> = results.iter().filter(|r| !r.pass).collect();

    if failed_checks.is_empty() {
        return vec!["Binary is fully compliant with Betanet 1.1 specification".to_string()];
    }

    let mut steps = Vec::new();

    // Prioritize by severity
    let critical_checks: Vec<_> = failed_checks.iter()
        .filter(|r| matches!(r.severity, Severity::Critical))
        .collect();

    if !critical_checks.is_empty() {
        steps.push(format!("🚨 URGENT: Address {} critical compliance failures", critical_checks.len()));
        for check in critical_checks {
            steps.push(format!("   - {}: {}", check.id, check.name));
        }
    }

    let high_checks: Vec<_> = failed_checks.iter()
        .filter(|r| matches!(r.severity, Severity::High))
        .collect();

    if !high_checks.is_empty() {
        steps.push(format!("⚠️  HIGH PRIORITY: Fix {} high-severity issues", high_checks.len()));
    }

    steps.push("📚 Review Betanet 1.1 specification Section 11 for detailed requirements".to_string());
    steps.push("🔧 Consider using reference implementation or approved libraries".to_string());
    steps.push("🧪 Test with official Betanet compliance test suite".to_string());

    steps
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 * BETANET 1.1 §11 COMPLIANCE CHECK IMPLEMENTATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Each function below implements verification for a specific normative 
 * requirement from Betanet 1.1 Section 11. These are NOT generic binary
 * hygiene checks, but protocol-specific verification.
 */

/// §11.1: HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH
fn check_11_1_htx_transport(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.1", "HTX Transport Layer Implementation");

    // Check for HTX protocol implementation
    let htx_support = analyzer.detect_htx_protocol_support();

    if htx_support.has_implementation {
        if htx_support.supports_tcp_443 && htx_support.supports_quic_443 {
            if htx_support.has_origin_mirroring && htx_support.has_ech_support {
                result = result.pass_with_details(
                    &format!("Complete HTX implementation detected: TCP-443 ✓, QUIC-443 ✓, Origin Mirroring ✓, ECH ✓. Transport functions: {}", 
                             htx_support.detected_functions.join(", ")),
                    0.95
                );
            } else {
                result = result.fail_with_details(
                    &format!("HTX transport missing security features - Origin Mirroring: {}, ECH: {}", 
                             htx_support.has_origin_mirroring, htx_support.has_ech_support),
                    0.8,
                    Severity::High
                );
                result.add_recommendation("Implement TLS fingerprint origin mirroring and Encrypted Client Hello (ECH)");
            }
        } else {
            result = result.fail_with_details(
                &format!("HTX transport incomplete - TCP-443: {}, QUIC-443: {}", 
                         htx_support.supports_tcp_443, htx_support.supports_quic_443),
                0.6,
                Severity::Critical
            );
            result.add_recommendation("Implement both TCP-443 and QUIC-443 transport channels for HTX protocol");
        }
    } else {
        result = result.fail_with_details(
            "No HTX transport implementation detected. Missing core Betanet protocol layer.",
            0.9,
            Severity::Critical
        );
        result.add_recommendation("Implement HTX (Hypertext Transfer eXtension) transport protocol as specified in Betanet 1.1 §11.1");
    }

    result
}

/// §11.2: Negotiated-carrier, replay-bound access tickets with rate-limits
fn check_11_2_access_tickets(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.2", "Access Ticket System");

    let ticket_support = analyzer.detect_access_ticket_system();

    if ticket_support.has_ticket_system {
        let mut missing_features = Vec::new();

        if !ticket_support.supports_carrier_negotiation {
            missing_features.push("carrier negotiation");
        }
        if !ticket_support.has_replay_protection {
            missing_features.push("replay protection");
        }
        if !ticket_support.has_rate_limiting {
            missing_features.push("rate limiting");
        }
        if !ticket_support.supports_x25519_exchange {
            missing_features.push("X25519 key exchange");
        }

        if missing_features.is_empty() {
            result = result.pass_with_details(
                &format!("Complete access ticket system: {} carriers supported, replay protection ✓, rate limiting ✓", 
                         ticket_support.supported_carriers.len()),
                0.9
            );
        } else {
            result = result.fail_with_details(
                &format!("Access ticket system missing: {}", missing_features.join(", ")),
                0.7,
                Severity::High
            );
            result.add_recommendation("Implement missing access ticket features for secure authentication");
        }
    } else {
        result = result.fail_with_details(
            "No access ticket authentication system detected",
            0.95,
            Severity::Critical
        );
        result.add_recommendation("Implement negotiated-carrier access ticket system with replay protection");
    }

    result
}

/// §11.3: Inner Noise XK with key separation, nonce lifecycle, rekeying
fn check_11_3_noise_xk_handshake(analyzer: &ProtocolAnalyzer, crypto_analyzer: &CryptoAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.3", "Noise XK Handshake Protocol");

    let noise_support = analyzer.detect_noise_protocol();
    let crypto_support = crypto_analyzer.analyze_post_quantum_crypto();

    if noise_support.implements_noise_xk {
        let mut missing_features = Vec::new();

        if !crypto_support.has_kyber768 {
            missing_features.push("Kyber768 post-quantum KEX");
        }
        if !noise_support.has_key_separation {
            missing_features.push("proper key separation (K0c/K0s)");
        }
        if !noise_support.supports_rekeying {
            missing_features.push("KEY_UPDATE rekeying");
        }
        if !noise_support.has_nonce_management {
            missing_features.push("nonce lifecycle management");
        }

        if missing_features.is_empty() {
            result = result.pass_with_details(
                "Complete Noise XK implementation with post-quantum hybrid key exchange",
                0.95
            );
        } else {
            result = result.fail_with_details(
                &format!("Noise XK implementation missing: {}", missing_features.join(", ")),
                0.8,
                Severity::High
            );
            result.add_recommendation("Upgrade to hybrid X25519-Kyber768 key exchange (required from 2027-01-01)");
        }
    } else {
        result = result.fail_with_details(
            "No Noise XK handshake protocol implementation detected",
            0.9,
            Severity::Critical
        );
        result.add_recommendation("Implement Noise XK handshake with hybrid post-quantum cryptography");
    }

    result
}

/// §11.4: HTTP/2/3 emulation with adaptive cadences  
fn check_11_4_http_emulation(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.4", "HTTP/2/3 Emulation Layer");

    let http_support = analyzer.detect_http_emulation();

    if http_support.supports_http2 || http_support.supports_http3 {
        let mut features = Vec::new();
        if http_support.supports_http2 { features.push("HTTP/2"); }
        if http_support.supports_http3 { features.push("HTTP/3"); }
        if http_support.has_adaptive_cadence { features.push("adaptive PING cadence"); }
        if http_support.has_priority_frames { features.push("PRIORITY frames"); }
        if http_support.has_padding { features.push("idle padding"); }

        let completeness = features.len() as f32 / 5.0; // 5 total features

        if completeness >= 0.8 {
            result = result.pass_with_details(
                &format!("HTTP emulation layer implemented: {}", features.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("HTTP emulation incomplete: {} features missing", 5 - features.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Implement complete HTTP/2/3 emulation for traffic analysis resistance");
        }
    } else {
        result = result.fail_with_details(
            "No HTTP emulation layer detected",
            0.95,
            Severity::High
        );
        result.add_recommendation("Implement HTTP/2/3 protocol emulation for cover traffic");
    }

    result
}

/// §11.5: HTX-tunnelled transition for non-SCION links
fn check_11_5_scion_bridging(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.5", "SCION Network Bridging");

    let scion_support = analyzer.detect_scion_bridging();

    if scion_support.has_scion_support {
        if scion_support.has_gateway_functionality && scion_support.has_transition_control {
            result = result.pass_with_details(
                "SCION bridging implemented with gateway functionality and transition control",
                0.9
            );
        } else {
            result = result.fail_with_details(
                &format!("SCION bridging incomplete - Gateway: {}, Transition: {}", 
                         scion_support.has_gateway_functionality, scion_support.has_transition_control),
                0.7,
                Severity::Medium
            );
            result.add_recommendation("Complete SCION gateway with HTX tunnel transition mechanism");
        }
    } else {
        // SCION support is optional for many deployments
        result = result.pass_with_details(
            "SCION bridging not detected (optional for non-SCION deployments)",
            0.5
        );
    }

    result
}

/// §11.6: Betanet transport support
fn check_11_6_betanet_transports(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.6", "Betanet Protocol Transport");

    let transport_support = analyzer.detect_betanet_protocols();

    let required_protocols = vec!["/betanet/htx/1.1.0", "/betanet/htxquic/1.1.0"];
    let mut supported_protocols = Vec::new();
    let mut missing_protocols = Vec::new();

    for protocol in &required_protocols {
        if transport_support.supported_protocols.contains(&protocol.to_string()) {
            supported_protocols.push(*protocol);
        } else {
            missing_protocols.push(*protocol);
        }
    }

    if missing_protocols.is_empty() {
        let mut details = format!("Required Betanet protocols supported: {}", supported_protocols.join(", "));
        if transport_support.supported_protocols.contains(&"/betanet/webrtc/1.0.0".to_string()) {
            details.push_str(", WebRTC (optional) ✓");
        }

        result = result.pass_with_details(&details, 0.95);
    } else {
        result = result.fail_with_details(
            &format!("Missing required Betanet protocols: {}", missing_protocols.join(", ")),
            0.9,
            Severity::Critical
        );
        result.add_recommendation("Implement all required Betanet 1.1 transport protocol identifiers");
    }

    result
}

/// §11.7: Bootstrap via rotating rendezvous with PoW rate-limits
fn check_11_7_bootstrap_mechanism(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.7", "Network Bootstrap Mechanism");

    let bootstrap_support = analyzer.detect_bootstrap_mechanism();

    if bootstrap_support.has_rendezvous_system {
        let mut features = Vec::new();
        if bootstrap_support.has_beacon_set { features.push("BeaconSet"); }
        if bootstrap_support.has_proof_of_work { features.push("PoW rate limiting"); }
        if bootstrap_support.supports_mdns { features.push("mDNS service"); }
        if bootstrap_support.supports_bluetooth { features.push("Bluetooth LE"); }

        let feature_score = features.len() as f32 / 4.0;

        if feature_score >= 0.75 {
            result = result.pass_with_details(
                &format!("Bootstrap mechanism implemented: {}", features.join(", ")),
                feature_score
            );
        } else {
            result = result.fail_with_details(
                &format!("Bootstrap mechanism incomplete: missing {}", 4 - features.len()),
                feature_score,
                Severity::Medium
            );
            result.add_recommendation("Complete bootstrap implementation with BeaconSet and PoW rate limiting");
        }
    } else {
        result = result.fail_with_details(
            "No rotating rendezvous bootstrap mechanism detected",
            0.9,
            Severity::High
        );
        result.add_recommendation("Implement rotating rendezvous DHT for network bootstrap");
    }

    result
}

/// §11.8: BeaconSet mixnode selection with path diversity
fn check_11_8_mixnode_selection(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.8", "Mixnode Selection Algorithm");

    let mixnode_support = analyzer.detect_mixnode_selection();

    if mixnode_support.implements_nym_integration {
        let mut features = Vec::new();
        if mixnode_support.uses_beacon_set_randomness { features.push("BeaconSet randomness"); }
        if mixnode_support.has_per_stream_entropy { features.push("per-stream entropy"); }
        if mixnode_support.uses_vrf_selection { features.push("VRF selection"); }
        if mixnode_support.ensures_path_diversity { features.push("AS path diversity"); }

        let completeness = features.len() as f32 / 4.0;

        if completeness >= 0.75 {
            result = result.pass_with_details(
                &format!("Mixnode selection implemented: {}", features.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("Mixnode selection incomplete: {} features missing", 4 - features.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Enhance mixnode selection with BeaconSet randomness and path diversity");
        }
    } else {
        result = result.fail_with_details(
            "No Nym mixnet integration detected",
            0.9,
            Severity::High
        );
        result.add_recommendation("Integrate with Nym mixnet for traffic anonymization");
    }

    result
}

/// §11.9: Finality-bound 2-of-3 alias ledger verification
fn check_11_9_alias_ledger(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.9", "Alias Ledger System");

    let ledger_support = analyzer.detect_alias_ledger();

    if ledger_support.has_alias_system {
        let mut features: Vec<String> = Vec::new();
        if ledger_support.implements_2of3_finality { features.push("2-of-3 finality".to_string()); }
        if ledger_support.supported_chains.len() >= 2 {
            features.push(format!("multi-chain ({} chains)", ledger_support.supported_chains.len()));
        }
        if ledger_support.has_emergency_advance { features.push("Emergency Advance".to_string()); }

        let completeness = if ledger_support.supported_chains.len() >= 2 { 1.0 } else { 0.6 };

        if completeness >= 0.8 {
            result = result.pass_with_details(
                &format!("Alias ledger system: {} | Chains: {}",
                         features.join(", "), ledger_support.supported_chains.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("Alias ledger incomplete: need at least 2 supported chains, have {}", 
                         ledger_support.supported_chains.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Support at least 2 blockchain networks (Handshake, Filecoin, Ethereum L2)");
        }
    } else {
        result = result.fail_with_details(
            "No alias ledger system detected",
            0.95,
            Severity::High
        );
        result.add_recommendation("Implement finality-bound 2-of-3 alias ledger with multi-chain support");
    }

    result
}

/// §11.10: 128-B Cashu vouchers with PoW adverts
fn check_11_10_cashu_vouchers(analyzer: &ProtocolAnalyzer, crypto_analyzer: &CryptoAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.10", "Cashu Payment System");

    let cashu_support = analyzer.detect_cashu_system();
    let frost_support = crypto_analyzer.detect_frost_signatures();

    if cashu_support.has_cashu_implementation {
        let mut features = Vec::new();
        if frost_support.supports_frost_ed25519 { features.push("FROST-Ed25519 mints"); }
        if cashu_support.supports_128b_vouchers { features.push("128-byte vouchers"); }
        if cashu_support.has_lightning_settlement { features.push("Lightning settlement"); }
        if cashu_support.has_keyset_management { features.push("keyset management"); }

        let completeness = features.len() as f32 / 4.0;

        if completeness >= 0.75 {
            result = result.pass_with_details(
                &format!("Cashu payment system: {}", features.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("Cashu system incomplete: {} features missing", 4 - features.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Complete Cashu implementation with FROST-Ed25519 and Lightning settlement");
        }
    } else {
        result = result.fail_with_details(
            "No Cashu payment system detected",
            0.9,
            Severity::Medium // Lower severity as payments might be optional
        );
        result.add_recommendation("Implement Cashu ecash system for micropayments and PoW adverts");
    }

    result
}

/// §11.11: Governance with anti-concentration caps and diversity checks
fn check_11_11_governance(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.11", "Network Governance System");

    let governance_support = analyzer.detect_governance_system();

    if governance_support.has_governance_system {
        let mut features = Vec::new();
        if governance_support.implements_voting_power { features.push("voting power calculation"); }
        if governance_support.has_uptime_scoring { features.push("uptime scoring"); }
        if governance_support.has_as_concentration_caps { features.push("AS concentration caps"); }
        if governance_support.implements_quorum_requirements { features.push("quorum requirements"); }
        if governance_support.ensures_partition_safety { features.push("partition safety"); }

        let completeness = features.len() as f32 / 5.0;

        if completeness >= 0.8 {
            result = result.pass_with_details(
                &format!("Governance system implemented: {}", features.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("Governance system incomplete: {} features missing", 5 - features.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Complete governance with anti-concentration and diversity mechanisms");
        }
    } else {
        result = result.fail_with_details(
            "No network governance system detected",
            0.9,
            Severity::Medium
        );
        result.add_recommendation("Implement governance system with voting power and concentration caps");
    }

    result
}

/// §11.12: Anti-correlation fallback with cover connections
fn check_11_12_anticorrelation_fallback(analyzer: &ProtocolAnalyzer) -> CheckResult {
    let mut result = CheckResult::new("BN-11.12", "Anti-Correlation Measures");

    let anticorr_support = analyzer.detect_anticorrelation_measures();

    if anticorr_support.has_fallback_mechanisms {
        let mut features = Vec::new();
        if anticorr_support.supports_udp_tcp_fallback { features.push("UDP→TCP fallback"); }
        if anticorr_support.implements_cover_connections { features.push("cover connections"); }
        if anticorr_support.has_randomized_timing { features.push("randomized timing"); }
        if anticorr_support.supports_masque { features.push("MASQUE tunneling"); }

        let completeness = features.len() as f32 / 4.0;

        if completeness >= 0.75 {
            result = result.pass_with_details(
                &format!("Anti-correlation measures: {}", features.join(", ")),
                completeness
            );
        } else {
            result = result.fail_with_details(
                &format!("Anti-correlation incomplete: {} features missing", 4 - features.len()),
                completeness,
                Severity::Medium
            );
            result.add_recommendation("Implement complete anti-correlation suite with cover traffic");
        }
    } else {
        result = result.fail_with_details(
            "No anti-correlation fallback mechanisms detected",
            0.9,
            Severity::High
        );
        result.add_recommendation("Implement anti-correlation measures with UDP/TCP fallback and cover connections");
    }

    result
}

/// §11.13: SLSA 3 provenance artifacts for reproducible builds
fn check_11_13_slsa_provenance(meta: &BinaryMeta) -> CheckResult {
    let mut result = CheckResult::new("BN-11.13", "Build Integrity & SLSA Provenance");

    let mut features = Vec::new();
    let mut missing_features = Vec::new();

    // Check build reproducibility
    if meta.build_reproducibility.has_build_id {
        features.push(format!("Build ID ({})", 
                            meta.build_reproducibility.build_id_type.as_ref().unwrap_or(&"unknown".to_string())));
    } else {
        missing_features.push("Build ID");
    }

    // Check deterministic build indicators
    if !meta.build_reproducibility.deterministic_indicators.is_empty() {
        features.push(format!("Deterministic indicators ({})", 
                            meta.build_reproducibility.deterministic_indicators.len()));
    } else {
        missing_features.push("Deterministic build indicators");
    }

    // Check for embedded timestamps (bad for reproducibility)
    if !meta.build_reproducibility.timestamp_embedded {
        features.push("No embedded timestamps".to_string());
    } else {
        missing_features.push("Deterministic timestamps");
    }

    // Check for SLSA/provenance indicators in strings or symbols
    let has_slsa_indicators = meta.strings.iter().any(|s| 
        s.contains("SLSA") || s.contains("slsa") || s.contains("provenance")
    ) || meta.imported_symbols.iter().any(|s| 
        s.contains("slsa") || s.contains("provenance") || s.contains("attestation")
    );

    if has_slsa_indicators {
        features.push("SLSA provenance support".to_string());
    } else {
        missing_features.push("SLSA provenance");
    }

    // Check for build attestation capabilities
    let has_attestation = meta.section_names.iter().any(|s| 
        s.contains("signature") || s.contains("sign") || s.contains("attest")
    ) || meta.imported_symbols.iter().any(|s|
        s.contains("sign") || s.contains("verify") || s.contains("attest")
    );

    if has_attestation {
        features.push("Build attestation".to_string());
    } else {
        missing_features.push("Build attestation");
    }

    let completeness = features.len() as f32 / (features.len() + missing_features.len()) as f32;

    if completeness >= 0.8 {
        result = result.pass_with_details(
            &format!("Build integrity verified: {} | Build ID: {:?}", 
                     features.join(", "), 
                     meta.build_reproducibility.build_id_value.as_ref().map(|v| &v[..8]).unwrap_or("none")),
            completeness
        );
    } else {
        result = result.fail_with_details(
            &format!("Build integrity insufficient: missing {} | Present: {}", 
                     missing_features.join(", "), features.join(", ")),
            completeness,
            Severity::High
        );
        result.add_recommendation("Implement SLSA Level 3 provenance with reproducible build pipeline");
        result.add_recommendation("Use SOURCE_DATE_EPOCH and deterministic build flags");
        result.add_recommendation("Generate and verify cryptographic build attestations");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::*;
    use std::collections::HashMap;

    fn create_test_binary_meta() -> BinaryMeta {
        BinaryMeta {
            path: std::path::PathBuf::from("test_binary"),
            format: BinFormat::Elf,
            size_bytes: 1000000,
            strings: vec![
                "HTX".to_string(),
                "/betanet/htx/1.1.0".to_string(),
                "/betanet/htxquic/1.1.0".to_string(),
                "SLSA".to_string(),
                "provenance".to_string(),
            ],
            sha256: "test_hash".to_string(),
            needed_libs: vec!["libquic.so".to_string()],
            raw: vec![],
            embedded_files: vec![],
            compiler_info: None,
            build_environment: BuildEnvironment {
                build_tool: None,
                build_version: None,
                build_timestamp: None,
                environment_variables: HashMap::new(),
            },
            crypto_components: vec![],
            static_libraries: vec![],
            licenses: vec![],
            betanet_indicators: BetanetIndicators {
                htx_transport: vec!["HTX".to_string()],
                protocol_versions: vec!["/betanet/htx/1.1.0".to_string()],
                crypto_protocols: vec![],
                network_transports: vec![],
                p2p_protocols: vec![],
                governance_indicators: vec![],
            },
            build_reproducibility: BuildReproducibility {
                has_build_id: true,
                build_id_type: Some("GNU Build ID".to_string()),
                build_id_value: Some("deadbeef".to_string()),
                deterministic_indicators: vec!["SOURCE_DATE_EPOCH".to_string()],
                timestamp_embedded: false,
            },
            imported_symbols: vec![],
            exported_symbols: vec![],
            section_names: vec![],
            dynamic_dependencies: vec![],
        }
    }

    #[test]
    fn test_run_all_checks_returns_13_results() {
        let meta = create_test_binary_meta();
        let results = run_all_checks(&meta);
        for result in &results {
            log::debug!("Check Result: ID={}, Pass={}, Details={}", result.id, result.pass, result.details);
        }

        assert_eq!(results.len(), 13, "Should return exactly 13 Betanet 1.1 compliance checks");

        // Verify all check IDs are present and correctly formatted
        let expected_ids: Vec<String> = (1..=13).map(|i| format!("BN-11.{}", i)).collect();
        let actual_ids: Vec<String> = results.iter().map(|r| r.id.clone()).collect();

        assert_eq!(actual_ids, expected_ids, "Check IDs should be BN-11.1 through BN-11.13");
    }

    #[test]
    fn test_check_result_structure() {
        let meta = create_test_binary_meta();
        let results = run_all_checks(&meta);

        for result in results {
            assert!(!result.id.is_empty(), "Check ID should not be empty");
            assert!(!result.name.is_empty(), "Check name should not be empty");
            assert!(!result.details.is_empty(), "Check details should not be empty");
            assert!(result.confidence >= 0.0 && result.confidence <= 1.0, "Confidence should be between 0 and 1");
        }
    }

    #[test]
    fn test_compliance_report_generation() {
        use tempfile::NamedTempFile;

        let meta = create_test_binary_meta();
        let results = run_all_checks(&meta);
        let temp_file = NamedTempFile::new().unwrap();

        write_report_json(&temp_file.path().to_path_buf(), "test_binary", &results).unwrap();

        let report_content = std::fs::read_to_string(temp_file.path()).unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_content).unwrap();

        assert_eq!(report["metadata"]["spec_version"], "Betanet 1.1");
        assert_eq!(report["summary"]["total_checks"], 13);
        assert!(report["detailed_results"].is_array());
    }
}
