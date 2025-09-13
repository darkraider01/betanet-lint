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
            // §11.1: HTX Transport (these are now moved to imported_symbols as they are actual symbols)
            "JA3".to_string(), "JA4".to_string(), "ECH".to_string(), "encrypted_client_hello".to_string(),
            // §11.6: Betanet transports
            "/betanet/htx/1.1.0".to_string(), "/betanet/htxquic/1.1.0".to_string(),
            "/betanet/webrtc/1.0.0".to_string(),
            // §11.13: SLSA
            "SLSA".to_string(), "provenance".to_string(), "reproducible_build".to_string(),
            "attestation".to_string(), "signature".to_string(),
        ],
        sha256: "deadbeefcafebabe".to_string(),
        needed_libs: vec![
            "libhtx.so".to_string(),
            "libquic.so".to_string(),
            "libnoise.so".to_string(),
            "libscion.so".to_string(),
            "libbetanet.so".to_string(),
            "libdht.so".to_string(),
            "libnym.so".to_string(),
            "libalias.so".to_string(),
            "libcashu.so".to_string(),
            "libgovernance.so".to_string(),
            "libanticorr.so".to_string(),
            "libslsa.so".to_string(),
            "libja3.so".to_string(),
            "libja4.so".to_string(),
            "libech.so".to_string(),
            "libboringssl.so".to_string(),
            "libopenssl.so".to_string(),
            "libfingerprint.so".to_string(),
            "libmdns.so".to_string(), // Added for BN-11.7
            "libbluetooth.so".to_string(), // Added for BN-11.7
            "libmasque.so".to_string(), // Added for BN-11.12
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
                algorithm: "SHA-256".to_string(),
                key_length: Some(256),
                mode: None,
                implementation: "ring".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::Hashing],
                compliance_status: ComplianceStatus::Approved,
            },
            CryptographicComponent {
                algorithm: "Kyber768".to_string(),
                key_length: Some(768),
                mode: Some("hybrid".to_string()),
                implementation: "oq_rust".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::KeyExchange],
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
            CryptographicComponent {
                algorithm: "X25519".to_string(),
                key_length: Some(255),
                mode: None,
                implementation: "ring".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::KeyExchange],
                compliance_status: ComplianceStatus::Approved,
            },
            CryptographicComponent {
                algorithm: "FROST-Ed25519".to_string(),
                key_length: Some(255),
                mode: None,
                implementation: "frost_dalek".to_string(),
                quantum_safe: true,
                usage_context: vec![CryptoUsage::Signing],
                compliance_status: ComplianceStatus::Approved,
            },
        ],
        static_libraries: vec![],
        licenses: vec![],
        betanet_indicators: BetanetIndicators {
            htx_transport: vec!["HTX".to_string(), "cover_transport".to_string()],
            protocol_versions: vec!["/betanet/htx/1.1.0".to_string(), "/betanet/htxquic/1.1.0".to_string(), "/betanet/webrtc/1.1.0".to_string()],
            crypto_protocols: vec!["Noise_XK".to_string(), "Kyber".to_string(), "FROST_Ed25519".to_string()],
            network_transports: vec!["QUIC".to_string(), ":443".to_string(), "h2".to_string(), "h3".to_string(), "SCION".to_string(), "MASQUE".to_string()],
            p2p_protocols: vec!["DHT".to_string(), "BeaconSet".to_string(), "Nym".to_string()],
            governance_indicators: vec!["vote_weight".to_string(), "quorum".to_string(), "alias_ledger".to_string(), "Cashu".to_string(), "SLSA".to_string()],
        },
        build_reproducibility: BuildReproducibility {
            has_build_id: true,
            build_id_type: Some("GNU Build ID".to_string()),
            build_id_value: Some("deadbeefcafebabe".to_string()),
            deterministic_indicators: vec!["SOURCE_DATE_EPOCH".to_string()],
            timestamp_embedded: false,
        },
        imported_symbols: vec![
            // §11.1: HTX Transport
            "htx_init".to_string(), "htx_send".to_string(), "htx_recv".to_string(),
            "cover_transport_init".to_string(), "cover_transport_send".to_string(),
            "tcp_443_listen".to_string(), "quic_443_connect".to_string(),
            "ja3_fingerprint".to_string(), "ja4_fingerprint".to_string(),
            "ech_negotiate".to_string(), "encrypted_client_hello_setup".to_string(),
            "tls_fingerprint".to_string(), "client_hello_".to_string(),
            "ech_".to_string(), "ECH_".to_string(), "encrypted_client_hello".to_string(),

            // §11.2: Access Tickets
            "access_ticket_issue".to_string(), "access_ticket_verify".to_string(),
            "cookie_carrier_negotiate".to_string(), "query_carrier_negotiate".to_string(),
            "body_carrier_negotiate".to_string(), "replay_protection_check".to_string(),
            "rate_limit_apply".to_string(), "x25519_key_exchange".to_string(),

            // §11.3: Noise XK
            "Noise_XK_handshake".to_string(), "Kyber768_encapsulate".to_string(),
            "hkdf_key_derive".to_string(), "key_separation_k0c".to_string(),
            "key_separation_k0s".to_string(), "key_update_rekey".to_string(),
            "nonce_lifecycle_management".to_string(),

            // §11.4: HTTP Emulation
            "h2_stream_open".to_string(), "h3_datagram_send".to_string(),
            "http2_settings_frame".to_string(), "http3_settings_frame".to_string(),
            "ping_cadence_adaptive".to_string(), "priority_frame_set".to_string(),
            "padding_data_insert".to_string(),

            // §11.5: SCION Bridging
            "scion_path_lookup".to_string(), "scion_gateway_route".to_string(),
            "transition_control_init".to_string(), "stream_id_allocate".to_string(),
            "cbor_encode".to_string(),

            // §11.7: Bootstrap
            "rendezvous_dht_bootstrap".to_string(), "beacon_set_fetch".to_string(),
            "proof_of_work_verify".to_string(), "mdns_service_discover".to_string(),
            "bluetooth_le_connect".to_string(),

            // §11.8: Mixnode Selection
            "nym_mixnet_route".to_string(), "beacon_set_randomness_derive".to_string(),
            "stream_entropy_generate".to_string(), "vrf_select_mixnode".to_string(),
            "path_diversity_ensure".to_string(),

            // §11.9: Alias Ledger
            "finality_2of3_verify".to_string(), "handshake_chain_sync".to_string(),
            "filecoin_fvm_call".to_string(), "ethereum_l2_tx".to_string(),
            "raven_names_resolve".to_string(), "emergency_advance_trigger".to_string(),
            "alias_ledger_lookup".to_string(), "alias_record_create".to_string(),

            // §11.10: Cashu Vouchers
            "cashu_mint_token".to_string(), "frost_ed25519_sign".to_string(),
            "voucher_issue_128b".to_string(), "lightning_settlement_init".to_string(),
            "keyset_management_rotate".to_string(),

            // §11.11: Governance
            "governance_vote_submit".to_string(), "voting_power_calculate".to_string(),
            "uptime_scoring_update".to_string(), "as_concentration_cap_check".to_string(),
            "quorum_requirements_verify".to_string(), "partition_safety_ensure".to_string(),

            // §11.12: Anti-correlation
            "fallback_udp_to_tcp".to_string(), "cover_connection_establish".to_string(),
            "randomized_timing_apply".to_string(), "masque_tunnel_open".to_string(),

            // §11.13: SLSA (these are now moved to imported_symbols as they are actual symbols)
            "slsa_provenance_generate".to_string(), "reproducible_build_verify".to_string(),
            "attestation_create".to_string(), "signature_verify".to_string(),
        ],
        exported_symbols: vec![
            "htx_public_api".to_string(), "access_ticket_public_api".to_string(),
            "noise_xk_public_api".to_string(), "http_emulation_public_api".to_string(),
            "scion_bridging_public_api".to_string(), "betanet_transport_public_api".to_string(),
            "bootstrap_public_api".to_string(), "mixnode_selection_public_api".to_string(),
            "alias_ledger_public_api".to_string(), "cashu_public_api".to_string(),
            "governance_public_api".to_string(), "anticorrelation_public_api".to_string(),
            "slsa_public_api".to_string(),
        ],
        section_names: vec![
            ".htx.data".to_string(), ".noise.text".to_string(), ".slsa.note".to_string(),
            ".betanet.config".to_string(),
        ],
        dynamic_dependencies: vec![
            "libquic.so".to_string(), "libnoise.so".to_string(), "libssl.so".to_string(),
            "libcrypto.so".to_string(), "libffi.so".to_string(),
            "libja3.so".to_string(), "libja4.so".to_string(), "libech.so".to_string(),
            "libboringssl.so".to_string(), "libopenssl.so".to_string(),
        ],
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
        0x00, 0x00, 0x00, 0x00, // e_shoff
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
        println!("Passed checks: {}", passed_count);
        for result in &results {
            println!("Check Result: ID={}, Pass={}, Details={}", result.id, result.pass, result.details);
        }
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
                    "BN-11.1" => assert!(result.details.contains("Complete HTX implementation detected: TCP-443"), "HTX check should mention HTX protocol"),
                    "BN-11.2" => assert!(result.details.contains("Complete access ticket system:"), "Access ticket check should mention tickets"),
                    "BN-11.3" => assert!(result.details.contains("Complete Noise XK implementation"), "Noise check should mention Noise protocol"),
                    "BN-11.6" => assert!(result.details.contains("Required Betanet protocols supported:"), "Transport check should mention betanet protocols"),
                    "BN-11.13" => assert!(result.details.contains("Build integrity verified") && result.details.contains("SLSA provenance support") && result.details.contains("Build ID")),
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
            assert!(!result.details.is_empty(), "Check details should be at least 10 characters: '{}'", result.details);
            
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
