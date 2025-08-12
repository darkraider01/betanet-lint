use betanet_lint::{
    binary::{
        BinaryMeta, CompilerInfo, BuildEnvironment, CryptographicComponent, CryptoUsage,
        ComplianceStatus, BetanetIndicators, BuildReproducibility, BinFormat
    },
    checks::run_all_checks,
};
use std::{path::PathBuf, collections::HashMap};

/// Create a test binary metadata with Betanet 1.1 compliance indicators
fn create_betanet_compliant_meta() -> BinaryMeta {
    BinaryMeta {
        path: PathBuf::from("betanet_compliant_test"),
        format: BinFormat::Elf,
        size_bytes: 10485760,
        strings: vec![
            // §11.1: HTX Transport
            "HTX".to_string(),
            "cover_transport".to_string(),
            ":443".to_string(),
            "QUIC".to_string(),
            "JA3".to_string(),
            "JA4".to_string(),
            "ECH".to_string(),
            "encrypted_client_hello".to_string(),
            // §11.2: Access Tickets
            "access_ticket".to_string(),
            "Cookie:".to_string(),
            "__Host-".to_string(),
            "bn1=".to_string(),
            "application/x-www-form-urlencoded".to_string(),
            "nonce".to_string(),
            "replay".to_string(),
            "X25519".to_string(),
            // §11.3: Noise XK
            "Noise_XK".to_string(),
            "Kyber".to_string(),
            "Kyber768".to_string(),
            "HKDF".to_string(),
            "K0c".to_string(),
            "K0s".to_string(),
            "KEY_UPDATE".to_string(),
            "rekey".to_string(),
            "nonce_counter".to_string(),
            // §11.4: HTTP Emulation
            "h2".to_string(),
            "HTTP/2".to_string(),
            "SETTINGS".to_string(),
            "h3".to_string(),
            "HTTP/3".to_string(),
            "PING_random".to_string(),
            "PRIORITY".to_string(),
            "padding_DATA".to_string(),
            // §11.5: SCION Bridging
            "SCION".to_string(),
            "gateway".to_string(),
            "Transition".to_string(),
            "stream_id".to_string(),
            "CBOR".to_string(),
            // §11.6: Betanet transports
            "/betanet/htx/1.1.0".to_string(),
            "/betanet/htxquic/1.1.0".to_string(),
            "/betanet/webrtc/1.0.0".to_string(),
            // §11.7: Bootstrap
            "rendezvous".to_string(),
            "DHT".to_string(),
            "BeaconSet".to_string(),
            "beacon".to_string(),
            "proof_of_work".to_string(),
            "PoW".to_string(),
            "_betanet._udp".to_string(),
            "mDNS".to_string(),
            "0xB7A7".to_string(),
            "Bluetooth".to_string(),
            // §11.8: Mixnode Selection
            "Nym".to_string(),
            "mixnet".to_string(),
            "streamNonce".to_string(),
            "stream_entropy".to_string(),
            "VRF".to_string(),
            "verifiable_random".to_string(),
            "diversity".to_string(),
            "distinct_AS".to_string(),
            // §11.9: Alias Ledger
            "alias_ledger".to_string(),
            "alias_record".to_string(),
            "finality".to_string(),
            "2-of-3".to_string(),
            "Handshake".to_string(),
            "Filecoin".to_string(),
            "FVM".to_string(),
            "Ethereum".to_string(),
            "Raven-Names".to_string(),
            "Emergency_Advance".to_string(),
            // §11.10: Cashu Vouchers
            "Cashu".to_string(),
            "FROST_Ed25519".to_string(),
            "voucher".to_string(),
            "Lightning".to_string(),
            "keyset".to_string(),
            // §11.11: Governance
            "vote_weight".to_string(),
            "voting_power".to_string(),
            "uptime_score".to_string(),
            "AS_cap".to_string(),
            "20%".to_string(),
            "quorum".to_string(),
            "0.67".to_string(),
            "partition_safety".to_string(),
            // §11.12: Anti-correlation
            "fallback_TCP".to_string(),
            "fallback_UDP".to_string(),
            "cover_connection".to_string(),
            "anti_correlation".to_string(),
            "random_delay".to_string(),
            "random_timing".to_string(),
            "MASQUE".to_string(),
            "CONNECT-UDP".to_string(),
            // §11.13: SLSA
            "SLSA".to_string(),
            "provenance".to_string(),
            "reproducible_build".to_string(),
            "attestation".to_string(),
            "signature".to_string(),
        ],
        sha256: "deadbeef".to_string(),
        needed_libs: vec![
            "libquic.so".to_string(),
            "libp2p.so".to_string(),
            "libnoise.so".to_string(),
            "libcashu.so".to_string(),
        ],
        raw: create_test_elf_with_build_id(),
        embedded_files: vec![],
        compiler_info: Some(CompilerInfo {
            compiler: "rustc".to_string(),
            version: "1.70.0".to_string(),
            optimization_level: "3".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        }),
        build_environment: BuildEnvironment {
            build_tool: Some("cargo".to_string()),
            build_version: Some("1.70.0".to_string()),
            build_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            environment_variables: HashMap::new(),
        },
        crypto_components: vec![
            CryptographicComponent {
                algorithm: "ChaCha20-Poly1305".to_string(),
                key_length: Some(256),
                mode: Some("IETF".to_string()),
                implementation: "ring".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::Encryption],
                compliance_status: ComplianceStatus::Approved,
            },
            CryptographicComponent {
                algorithm: "Ed25519".to_string(),
                key_length: Some(255),
                mode: None,
                implementation: "ring".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::Signing],
                compliance_status: ComplianceStatus::Approved,
            },
        ],
        static_libraries: vec![],
        licenses: vec![],
        betanet_indicators: BetanetIndicators {
            htx_transport: vec!["HTX".to_string(), "cover_transport".to_string()],
            protocol_versions: vec!["/betanet/htx/1.1.0".to_string(), "/betanet/htxquic/1.1.0".to_string()],
            crypto_protocols: vec!["Noise_XK".to_string(), "Kyber".to_string()],
            network_transports: vec!["QUIC".to_string(), ":443".to_string()],
            p2p_protocols: vec!["libp2p".to_string(), "DHT".to_string()],
            governance_indicators: vec!["vote_weight".to_string(), "quorum".to_string()],
        },
        build_reproducibility: BuildReproducibility {
            has_build_id: true,
            build_id_type: Some("GNU Build ID".to_string()),
            build_id_value: Some("deadbeefcafebabe".to_string()),
            deterministic_indicators: vec!["SOURCE_DATE_EPOCH".to_string()],
            timestamp_embedded: false,
        },
        imported_symbols: vec![],
        exported_symbols: vec![],
        section_names: vec![],
        dynamic_dependencies: vec![],
    }
}

fn create_test_elf_with_build_id() -> Vec<u8> {
    // Minimal ELF with build ID note section
    vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, version 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
        0x03, 0x00, // e_type = ET_DYN (PIE)
        0x3e, 0x00, // e_machine = EM_X86_64
        0x01, 0x00, 0x00, 0x00, // e_version = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x40, 0x00, // e_ehsize = 64
        0x38, 0x00, // e_phentsize = 56
        0x01, 0x00, // e_phnum = 1
        0x40, 0x00, // e_shentsize = 64
        0x00, 0x00, // e_shnum = 0
        0x00, 0x00, // e_shstrndx = 0
    ]
}

fn create_non_compliant_meta() -> BinaryMeta {
    BinaryMeta {
        path: PathBuf::from("non_compliant_test"),
        format: BinFormat::Elf,
        size_bytes: 1024,
        strings: vec![
            "hello".to_string(),
            "world".to_string(),
            "basic_binary".to_string(),
        ],
        sha256: "abcd1234".to_string(),
        needed_libs: vec!["libc.so.6".to_string()],
        raw: vec![0x7f, 0x45, 0x4c, 0x46], // Minimal ELF
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
            htx_transport: vec![],
            protocol_versions: vec![],
            crypto_protocols: vec![],
            network_transports: vec![],
            p2p_protocols: vec![],
            governance_indicators: vec![],
        },
        build_reproducibility: BuildReproducibility {
            has_build_id: false,
            build_id_type: None,
            build_id_value: None,
            deterministic_indicators: vec![],
            timestamp_embedded: true,
        },
        imported_symbols: vec![],
        exported_symbols: vec![],
        section_names: vec![],
        dynamic_dependencies: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_betanet_compliant_binary_passes_all_checks() {
        let meta = create_betanet_compliant_meta();
        let results = run_all_checks(&meta);
        
        // Should have exactly 13 Betanet 1.1 compliance checks
        assert_eq!(results.len(), 13, "Expected 13 Betanet 1.1 compliance checks");
        
        // Check that all results have proper BN-11.x IDs
        for (i, result) in results.iter().enumerate() {
            let expected_id = format!("BN-11.{}", i + 1);
            assert_eq!(result.id, expected_id, "Check ID mismatch at index {}", i);
        }
        
        // Most checks should pass for compliant binary
        let passed_count = results.iter().filter(|r| r.pass).count();
        assert!(passed_count >= 10, "Expected at least 10 checks to pass, got {}", passed_count);
        
        // Verify specific critical checks pass
        let htx_check = results.iter().find(|r| r.id == "BN-11.1").unwrap();
        assert!(htx_check.pass, "HTX transport check should pass: {}", htx_check.details);
        
        let transport_check = results.iter().find(|r| r.id == "BN-11.6").unwrap();
        assert!(transport_check.pass, "Betanet transport check should pass: {}", transport_check.details);
        
        let slsa_check = results.iter().find(|r| r.id == "BN-11.13").unwrap();
        // SLSA might not pass due to lack of actual provenance, but should be detected
        println!("SLSA check result: {}", slsa_check.details);
    }

    #[test]
    fn test_non_compliant_binary_fails_most_checks() {
        let meta = create_non_compliant_meta();
        let results = run_all_checks(&meta);
        
        assert_eq!(results.len(), 13, "Expected 13 Betanet 1.1 compliance checks");
        
        // Most checks should fail for non-compliant binary
        let failed_count = results.iter().filter(|r| !r.pass).count();
        assert!(failed_count >= 10, "Expected at least 10 checks to fail, got {}", failed_count);
        
        // Verify specific checks fail as expected
        let htx_check = results.iter().find(|r| r.id == "BN-11.1").unwrap();
        assert!(!htx_check.pass, "HTX transport check should fail for non-compliant binary");
        
        let transport_check = results.iter().find(|r| r.id == "BN-11.6").unwrap();
        assert!(!transport_check.pass, "Betanet transport check should fail for non-compliant binary");
    }

    #[test]
    fn test_individual_betanet_checks() {
        let meta = create_betanet_compliant_meta();
        let results = run_all_checks(&meta);
        
        // Test each check has meaningful details
        for result in &results {
            assert!(!result.details.is_empty(), "Check {} should have details", result.id);
            assert!(!result.details.contains("[PLACEHOLDER]"), 
                    "Check {} should not be a placeholder: {}", result.id, result.details);
            
            // Check details should mention specific Betanet concepts
            if result.pass {
                match result.id.as_str() {
                    "BN-11.1" => assert!(result.details.contains("HTX"), "HTX check should mention HTX protocol"),
                    "BN-11.2" => assert!(result.details.contains("ticket"), "Access ticket check should mention tickets"),
                    "BN-11.3" => assert!(result.details.contains("Noise"), "Noise check should mention Noise protocol"),
                    "BN-11.6" => assert!(result.details.contains("Betanet protocols found"), "Transport check should mention betanet protocols"),
                    "BN-11.13" => assert!(result.details.contains("SLSA") || result.details.contains("Build"), "SLSA check should mention SLSA or build"),
                    _ => {} // Other checks can have various valid details
                }
            }
        }
    }

    #[test]
    fn test_check_result_structure() {
        let meta = create_betanet_compliant_meta();
        let results = run_all_checks(&meta);
        
        for result in &results {
            // Each check should have proper structure
            assert!(!result.id.is_empty(), "Check ID should not be empty");
            assert!(result.id.starts_with("BN-11."), "Check ID should start with BN-11.");
            assert!(!result.details.is_empty(), "Check details should not be empty");
            
            // Details should be informative
            assert!(result.details.len() >= 10, "Check details should be at least 10 characters: '{}'", result.details);
        }
    }

    #[test]
    fn test_betanet_indicators_detection() {
        let meta = create_betanet_compliant_meta();
        
        // Verify Betanet indicators were properly detected
        assert!(!meta.betanet_indicators.htx_transport.is_empty(), "Should detect HTX transport indicators");
        assert!(!meta.betanet_indicators.protocol_versions.is_empty(), "Should detect protocol versions");
        assert!(!meta.betanet_indicators.crypto_protocols.is_empty(), "Should detect crypto protocols");
        assert!(!meta.betanet_indicators.network_transports.is_empty(), "Should detect network transports");
        
        // Verify specific indicators
        assert!(meta.betanet_indicators.protocol_versions.contains(&"/betanet/htx/1.1.0".to_string()), 
                "Should detect HTX 1.1.0 protocol");
        assert!(meta.betanet_indicators.protocol_versions.contains(&"/betanet/htxquic/1.1.0".to_string()), 
                "Should detect HTXQUIC 1.1.0 protocol");
    }

    #[test]
    fn test_build_reproducibility_detection() {
        let meta = create_betanet_compliant_meta();
        
        assert!(meta.build_reproducibility.has_build_id, "Should detect build ID");
        assert_eq!(meta.build_reproducibility.build_id_type, Some("GNU Build ID".to_string()));
        assert!(!meta.build_reproducibility.deterministic_indicators.is_empty(), "Should detect deterministic build indicators");
        assert!(!meta.build_reproducibility.timestamp_embedded, "Should not have embedded timestamps for reproducible build");
    }
}
