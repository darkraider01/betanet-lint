//! Protocol Analysis Module
//!
//! This module provides sophisticated analysis of binary files to detect
//! actual protocol implementations rather than relying on string scanning.
//! It uses symbol analysis, binary structure inspection, and behavioral
//! pattern detection.

use crate::binary::BinaryMeta;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub struct ProtocolAnalyzer<'a> {
    meta: &'a BinaryMeta,
    symbol_analyzer: SymbolAnalyzer<'a>,
    section_analyzer: SectionAnalyzer<'a>,
    import_analyzer: ImportAnalyzer<'a>,
}

impl<'a> ProtocolAnalyzer<'a> {
    pub fn new(meta: &'a BinaryMeta) -> Self {
        Self {
            meta,
            symbol_analyzer: SymbolAnalyzer::new(meta),
            section_analyzer: SectionAnalyzer::new(meta),
            import_analyzer: ImportAnalyzer::new(meta),
        }
    }

    pub fn detect_htx_protocol_support(&self) -> HTXProtocolSupport {
        let mut support = HTXProtocolSupport::default();

        // Look for HTX implementation symbols
        support.detected_functions = self.symbol_analyzer.find_htx_symbols();
        support.has_implementation = !support.detected_functions.is_empty();

        // Check for TCP/QUIC transport support
        support.supports_tcp_443 = self.symbol_analyzer.has_tcp_443_support() || 
                                  self.import_analyzer.imports_tcp_libraries();
        support.supports_quic_443 = self.symbol_analyzer.has_quic_support() ||
                                   self.import_analyzer.imports_quic_libraries();

        // Check for TLS origin mirroring capabilities
        support.has_origin_mirroring = self.symbol_analyzer.has_tls_fingerprinting() ||
                                      self.import_analyzer.imports_tls_fingerprint_libs();

        // Check for ECH (Encrypted Client Hello) support
        support.has_ech_support = self.symbol_analyzer.has_ech_symbols() ||
                                 self.import_analyzer.imports_ech_libraries();

        support
    }

    pub fn detect_access_ticket_system(&self) -> AccessTicketSupport {
        let mut support = AccessTicketSupport::default();

        // Look for access ticket implementation
        support.has_ticket_system = self.symbol_analyzer.has_ticket_symbols() ||
                                   self.section_analyzer.has_ticket_sections();

        // Check carrier negotiation support
        support.supports_carrier_negotiation = self.symbol_analyzer.has_carrier_negotiation();
        support.supported_carriers = self.detect_supported_carriers();

        // Check security features
        support.has_replay_protection = self.symbol_analyzer.has_replay_protection();
        support.has_rate_limiting = self.symbol_analyzer.has_rate_limiting();
        support.supports_x25519_exchange = self.symbol_analyzer.has_x25519_symbols();

        support
    }

    pub fn detect_noise_protocol(&self) -> NoiseProtocolSupport {
        let mut support = NoiseProtocolSupport::default();

        // Check for Noise protocol implementation
        support.implements_noise_xk = self.symbol_analyzer.has_noise_xk_symbols() ||
                                     self.import_analyzer.imports_noise_libraries();

        // Check key management features
        support.has_key_separation = self.symbol_analyzer.has_key_separation_symbols();
        support.supports_rekeying = self.symbol_analyzer.has_rekeying_symbols();
        support.has_nonce_management = self.symbol_analyzer.has_nonce_management();

        support
    }

    pub fn detect_http_emulation(&self) -> HTTPEmulationSupport {
        let mut support = HTTPEmulationSupport::default();

        // Check HTTP/2 and HTTP/3 support through imports and symbols
        support.supports_http2 = self.import_analyzer.imports_h2_libraries() ||
                                self.symbol_analyzer.has_h2_symbols();
        support.supports_http3 = self.import_analyzer.imports_h3_libraries() ||
                                self.symbol_analyzer.has_h3_symbols();

        // Check emulation features
        support.has_adaptive_cadence = self.symbol_analyzer.has_adaptive_cadence();
        support.has_priority_frames = self.symbol_analyzer.has_priority_frames();
        support.has_padding = self.symbol_analyzer.has_padding_support();

        support
    }

    pub fn detect_scion_bridging(&self) -> SCIONBridgingSupport {
        let mut support = SCIONBridgingSupport::default();

        support.has_scion_support = self.symbol_analyzer.has_scion_symbols() ||
                                   self.import_analyzer.imports_scion_libraries();
        support.has_gateway_functionality = self.symbol_analyzer.has_gateway_symbols();
        support.has_transition_control = self.symbol_analyzer.has_transition_control();

        support
    }

    pub fn detect_betanet_protocols(&self) -> BetanetProtocolSupport {
        let mut support = BetanetProtocolSupport::default();

        // Look for protocol version strings in a more sophisticated way
        // Check symbols, section names, and imported library names
        support.supported_protocols = self.detect_protocol_versions();

        support
    }

    pub fn detect_bootstrap_mechanism(&self) -> BootstrapSupport {
        let mut support = BootstrapSupport::default();

        support.has_rendezvous_system = self.symbol_analyzer.has_dht_symbols() ||
                                       self.import_analyzer.imports_dht_libraries();
        support.has_beacon_set = self.symbol_analyzer.has_beacon_symbols();
        support.has_proof_of_work = self.symbol_analyzer.has_pow_symbols();
        support.supports_mdns = self.import_analyzer.imports_mdns_libraries();
        support.supports_bluetooth = self.import_analyzer.imports_bluetooth_libraries();

        support
    }

    pub fn detect_mixnode_selection(&self) -> MixnodeSupport {
        let mut support = MixnodeSupport::default();

        support.implements_nym_integration = self.import_analyzer.imports_nym_libraries() ||
                                            self.symbol_analyzer.has_nym_symbols();
        support.uses_beacon_set_randomness = self.symbol_analyzer.has_beacon_randomness();
        support.has_per_stream_entropy = self.symbol_analyzer.has_stream_entropy();
        support.uses_vrf_selection = self.symbol_analyzer.has_vrf_symbols();
        support.ensures_path_diversity = self.symbol_analyzer.has_path_diversity();

        support
    }

    pub fn detect_alias_ledger(&self) -> AliasLedgerSupport {
        let mut support = AliasLedgerSupport::default();

        support.has_alias_system = self.symbol_analyzer.has_alias_symbols() ||
                                  self.section_analyzer.has_alias_sections();
        support.implements_2of3_finality = self.symbol_analyzer.has_finality_symbols();
        support.supported_chains = self.detect_supported_chains();
        support.has_emergency_advance = self.symbol_analyzer.has_emergency_advance();

        support
    }

    pub fn detect_cashu_system(&self) -> CashuSupport {
        let mut support = CashuSupport::default();

        support.has_cashu_implementation = self.symbol_analyzer.has_cashu_symbols() ||
                                          self.import_analyzer.imports_cashu_libraries();
        support.supports_128b_vouchers = self.symbol_analyzer.has_voucher_symbols();
        support.has_lightning_settlement = self.import_analyzer.imports_lightning_libraries();
        support.has_keyset_management = self.symbol_analyzer.has_keyset_management();

        support
    }

    pub fn detect_governance_system(&self) -> GovernanceSupport {
        let mut support = GovernanceSupport::default();

        support.has_governance_system = self.symbol_analyzer.has_governance_symbols();
        support.implements_voting_power = self.symbol_analyzer.has_voting_symbols();
        support.has_uptime_scoring = self.symbol_analyzer.has_uptime_symbols();
        support.has_as_concentration_caps = self.symbol_analyzer.has_concentration_caps();
        support.implements_quorum_requirements = self.symbol_analyzer.has_quorum_symbols();
        support.ensures_partition_safety = self.symbol_analyzer.has_partition_safety();

        support
    }

    pub fn detect_anticorrelation_measures(&self) -> AnticorrelationSupport {
        let mut support = AnticorrelationSupport::default();

        support.has_fallback_mechanisms = self.symbol_analyzer.has_fallback_symbols();
        support.supports_udp_tcp_fallback = self.symbol_analyzer.has_udp_tcp_fallback();
        support.implements_cover_connections = self.symbol_analyzer.has_cover_connection_symbols();
        support.has_randomized_timing = self.symbol_analyzer.has_timing_randomization();
        support.supports_masque = self.import_analyzer.imports_masque_libraries();

        support
    }

    fn detect_supported_carriers(&self) -> Vec<String> {
        let mut carriers = Vec::new();

        if self.symbol_analyzer.has_cookie_carrier() { carriers.push("Cookie".to_string()); }
        if self.symbol_analyzer.has_query_carrier() { carriers.push("Query".to_string()); }
        if self.symbol_analyzer.has_body_carrier() { carriers.push("Body".to_string()); }

        carriers
    }

    fn detect_protocol_versions(&self) -> Vec<String> {
        let mut protocols = Vec::new();

        // Check for protocol version strings in symbols and sections
        let all_text_sources: Vec<&str> = self.meta.imported_symbols.iter()
            .chain(self.meta.exported_symbols.iter())
            .chain(self.meta.section_names.iter())
            .chain(self.meta.strings.iter())
            .map(|s| s.as_str())
            .collect();

        let betanet_protocols = [
            "/betanet/htx/1.1.0",
            "/betanet/htxquic/1.1.0",
            "/betanet/webrtc/1.0.0",
        ];

        for protocol in &betanet_protocols {
            if all_text_sources.iter().any(|&source| source.contains(protocol)) {
                protocols.push(protocol.to_string());
            }
        }

        protocols
    }

    fn detect_supported_chains(&self) -> Vec<String> {
        let mut chains = Vec::new();

        let chain_indicators = [
            ("Handshake", vec!["handshake", "HNS", "hsd"]),
            ("Filecoin", vec!["filecoin", "FIL", "lotus", "FVM"]),
            ("Ethereum", vec!["ethereum", "ETH", "geth", "raven-names"]),
        ];

        for (chain_name, indicators) in &chain_indicators {
            let found = indicators.iter().any(|&indicator| {
                self.meta.imported_symbols.iter().any(|s| s.to_lowercase().contains(&indicator.to_lowercase())) ||
                self.meta.needed_libs.iter().any(|s| s.to_lowercase().contains(&indicator.to_lowercase()))
            });

            if found {
                chains.push(chain_name.to_string());
            }
        }

        chains
    }
}

/// Symbol analyzer for detecting function and variable names that indicate protocol support
struct SymbolAnalyzer<'a> {
    imported_symbols: &'a [String],
    exported_symbols: &'a [String],
}

impl<'a> SymbolAnalyzer<'a> {
    fn new(meta: &'a BinaryMeta) -> Self {
        Self {
            imported_symbols: &meta.imported_symbols,
            exported_symbols: &meta.exported_symbols,
        }
    }

    fn find_htx_symbols(&self) -> Vec<String> {
        let htx_patterns = ["htx_", "HTX_", "cover_transport", "betanet_transport"];
        self.find_symbols_by_patterns(&htx_patterns)
    }

    fn has_tcp_443_support(&self) -> bool {
        let tcp_patterns = ["tcp_443", "bind_443", "listen_443", "server_443"];
        self.has_symbols_matching(&tcp_patterns)
    }

    fn has_quic_support(&self) -> bool {
        let quic_patterns = ["quic_", "QUIC_", "h3_", "HTTP3_"];
        self.has_symbols_matching(&quic_patterns)
    }

    fn has_tls_fingerprinting(&self) -> bool {
        let tls_patterns = ["ja3_", "ja4_", "tls_fingerprint", "client_hello_"];
        self.has_symbols_matching(&tls_patterns)
    }

    fn has_ech_symbols(&self) -> bool {
        let ech_patterns = ["ech_", "ECH_", "encrypted_client_hello"];
        self.has_symbols_matching(&ech_patterns)
    }

    fn has_ticket_symbols(&self) -> bool {
        let ticket_patterns = ["ticket_", "access_ticket", "auth_ticket"];
        self.has_symbols_matching(&ticket_patterns)
    }

    fn has_carrier_negotiation(&self) -> bool {
        let carrier_patterns = ["negotiate_carrier", "carrier_select", "transport_negotiate"];
        self.has_symbols_matching(&carrier_patterns)
    }

    fn has_replay_protection(&self) -> bool {
        let replay_patterns = ["replay_protect", "nonce_check", "sequence_verify"];
        self.has_symbols_matching(&replay_patterns)
    }

    fn has_rate_limiting(&self) -> bool {
        let rate_patterns = ["rate_limit", "throttle_", "bucket_"];
        self.has_symbols_matching(&rate_patterns)
    }

    fn has_x25519_symbols(&self) -> bool {
        let x25519_patterns = ["x25519_", "X25519_", "curve25519_"];
        self.has_symbols_matching(&x25519_patterns)
    }

    fn has_noise_xk_symbols(&self) -> bool {
        let noise_patterns = ["noise_xk", "NoiseXK", "NOISE_XK"];
        self.has_symbols_matching(&noise_patterns)
    }

    fn has_key_separation_symbols(&self) -> bool {
        let key_sep_patterns = ["k0c_", "k0s_", "key_separate", "hkdf_"];
        self.has_symbols_matching(&key_sep_patterns)
    }

    fn has_rekeying_symbols(&self) -> bool {
        let rekey_patterns = ["rekey_", "key_update", "KEY_UPDATE"];
        self.has_symbols_matching(&rekey_patterns)
    }

    fn has_nonce_management(&self) -> bool {
        let nonce_patterns = ["nonce_counter", "nonce_lifecycle", "nonce_manage"];
        self.has_symbols_matching(&nonce_patterns)
    }

    fn has_h2_symbols(&self) -> bool {
        let h2_patterns = ["h2_", "HTTP2_", "settings_", "stream_"];
        self.has_symbols_matching(&h2_patterns)
    }

    fn has_h3_symbols(&self) -> bool {
        let h3_patterns = ["h3_", "HTTP3_", "quic_stream"];
        self.has_symbols_matching(&h3_patterns)
    }

    fn has_adaptive_cadence(&self) -> bool {
        let cadence_patterns = ["ping_cadence", "adaptive_", "random_ping"];
        self.has_symbols_matching(&cadence_patterns)
    }

    fn has_priority_frames(&self) -> bool {
        let priority_patterns = ["priority_", "PRIORITY_", "stream_priority"];
        self.has_symbols_matching(&priority_patterns)
    }

    fn has_padding_support(&self) -> bool {
        let padding_patterns = ["padding_", "dummy_data", "pad_frame"];
        self.has_symbols_matching(&padding_patterns)
    }

    fn has_scion_symbols(&self) -> bool {
        let scion_patterns = ["scion_", "SCION_", "snet_"];
        self.has_symbols_matching(&scion_patterns)
    }

    fn has_gateway_symbols(&self) -> bool {
        let gateway_patterns = ["gateway_", "bridge_", "proxy_"];
        self.has_symbols_matching(&gateway_patterns)
    }

    fn has_transition_control(&self) -> bool {
        let transition_patterns = ["transition_", "control_stream", "cbor_"];
        self.has_symbols_matching(&transition_patterns)
    }

    fn has_dht_symbols(&self) -> bool {
        let dht_patterns = ["dht_", "DHT_", "kademlia_", "rendezvous_"];
        self.has_symbols_matching(&dht_patterns)
    }

    fn has_beacon_symbols(&self) -> bool {
        let beacon_patterns = ["beacon_", "BeaconSet", "beacon_set"];
        self.has_symbols_matching(&beacon_patterns)
    }

    fn has_pow_symbols(&self) -> bool {
        let pow_patterns = ["pow_", "proof_of_work", "hashcash_"];
        self.has_symbols_matching(&pow_patterns)
    }

    fn has_nym_symbols(&self) -> bool {
        let nym_patterns = ["nym_", "mixnet_", "mix_"];
        self.has_symbols_matching(&nym_patterns)
    }

    fn has_beacon_randomness(&self) -> bool {
        let beacon_rand_patterns = ["beacon_random", "beacon_entropy"];
        self.has_symbols_matching(&beacon_rand_patterns)
    }

    fn has_stream_entropy(&self) -> bool {
        let stream_patterns = ["stream_nonce", "stream_entropy"];
        self.has_symbols_matching(&stream_patterns)
    }

    fn has_vrf_symbols(&self) -> bool {
        let vrf_patterns = ["vrf_", "VRF_", "verifiable_random"];
        self.has_symbols_matching(&vrf_patterns)
    }

    fn has_path_diversity(&self) -> bool {
        let diversity_patterns = ["path_diversity", "as_diversity", "distinct_as"];
        self.has_symbols_matching(&diversity_patterns)
    }

    fn has_alias_symbols(&self) -> bool {
        let alias_patterns = ["alias_", "name_resolve", "ledger_"];
        self.has_symbols_matching(&alias_patterns)
    }

    fn has_finality_symbols(&self) -> bool {
        let finality_patterns = ["finality_", "2of3_", "consensus_"];
        self.has_symbols_matching(&finality_patterns)
    }

    fn has_emergency_advance(&self) -> bool {
        let emergency_patterns = ["emergency_advance", "force_finality"];
        self.has_symbols_matching(&emergency_patterns)
    }

    fn has_cashu_symbols(&self) -> bool {
        let cashu_patterns = ["cashu_", "ecash_", "blind_sign"];
        self.has_symbols_matching(&cashu_patterns)
    }

    fn has_voucher_symbols(&self) -> bool {
        let voucher_patterns = ["voucher_", "mint_", "redeem_"];
        self.has_symbols_matching(&voucher_patterns)
    }

    fn has_keyset_management(&self) -> bool {
        let keyset_patterns = ["keyset_", "mint_keys", "rotate_keys"];
        self.has_symbols_matching(&keyset_patterns)
    }

    fn has_governance_symbols(&self) -> bool {
        let gov_patterns = ["governance_", "vote_", "proposal_"];
        self.has_symbols_matching(&gov_patterns)
    }

    fn has_voting_symbols(&self) -> bool {
        let vote_patterns = ["vote_weight", "voting_power", "ballot_"];
        self.has_symbols_matching(&vote_patterns)
    }

    fn has_uptime_symbols(&self) -> bool {
        let uptime_patterns = ["uptime_", "availability_", "ping_"];
        self.has_symbols_matching(&uptime_patterns)
    }

    fn has_concentration_caps(&self) -> bool {
        let cap_patterns = ["as_cap", "concentration_", "diversity_"];
        self.has_symbols_matching(&cap_patterns)
    }

    fn has_quorum_symbols(&self) -> bool {
        let quorum_patterns = ["quorum_", "consensus_", "threshold_"];
        self.has_symbols_matching(&quorum_patterns)
    }

    fn has_partition_safety(&self) -> bool {
        let partition_patterns = ["partition_", "split_brain", "safety_"];
        self.has_symbols_matching(&partition_patterns)
    }

    fn has_fallback_symbols(&self) -> bool {
        let fallback_patterns = ["fallback_", "failover_", "backup_"];
        self.has_symbols_matching(&fallback_patterns)
    }

    fn has_udp_tcp_fallback(&self) -> bool {
        let udp_tcp_patterns = ["udp_fallback", "tcp_fallback", "protocol_switch"];
        self.has_symbols_matching(&udp_tcp_patterns)
    }

    fn has_cover_connection_symbols(&self) -> bool {
        let cover_patterns = ["cover_conn", "dummy_conn", "decoy_"];
        self.has_symbols_matching(&cover_patterns)
    }

    fn has_timing_randomization(&self) -> bool {
        let timing_patterns = ["random_delay", "jitter_", "timing_obf"];
        self.has_symbols_matching(&timing_patterns)
    }

    fn has_cookie_carrier(&self) -> bool {
        let cookie_patterns = ["cookie_", "Cookie", "__Host-"];
        self.has_symbols_matching(&cookie_patterns)
    }

    fn has_query_carrier(&self) -> bool {
        let query_patterns = ["query_param", "url_param", "bn1="];
        self.has_symbols_matching(&query_patterns)
    }

    fn has_body_carrier(&self) -> bool {
        let body_patterns = ["form_data", "urlencoded", "body_param"];
        self.has_symbols_matching(&body_patterns)
    }

    fn find_symbols_by_patterns(&self, patterns: &[&str]) -> Vec<String> {
        let mut found = Vec::new();

        for symbol in self.imported_symbols.iter().chain(self.exported_symbols.iter()) {
            for pattern in patterns {
                if symbol.contains(pattern) {
                    found.push(symbol.clone());
                    break;
                }
            }
        }

        found
    }

    fn has_symbols_matching(&self, patterns: &[&str]) -> bool {
        self.imported_symbols.iter().chain(self.exported_symbols.iter())
            .any(|symbol| patterns.iter().any(|&pattern| symbol.contains(pattern)))
    }
}

/// Section analyzer for detecting protocol support in binary sections
struct SectionAnalyzer<'a> {
    section_names: &'a [String],
}

impl<'a> SectionAnalyzer<'a> {
    fn new(meta: &'a BinaryMeta) -> Self {
        Self {
            section_names: &meta.section_names,
        }
    }

    fn has_ticket_sections(&self) -> bool {
        self.section_names.iter().any(|name| 
            name.contains("ticket") || name.contains("auth") || name.contains("access")
        )
    }

    fn has_alias_sections(&self) -> bool {
        self.section_names.iter().any(|name|
            name.contains("alias") || name.contains("name") || name.contains("ledger")
        )
    }
}

/// Import analyzer for detecting protocol support through library dependencies
struct ImportAnalyzer<'a> {
    needed_libs: &'a [String],
    dynamic_deps: &'a [String],
}

impl<'a> ImportAnalyzer<'a> {
    fn new(meta: &'a BinaryMeta) -> Self {
        Self {
            needed_libs: &meta.needed_libs,
            dynamic_deps: &meta.dynamic_dependencies,
        }
    }

    fn imports_tcp_libraries(&self) -> bool {
        self.has_lib_matching(&["libc", "socket", "net"])
    }

    fn imports_quic_libraries(&self) -> bool {
        self.has_lib_matching(&["quic", "h3", "quinn", "lsquic"])
    }

    fn imports_tls_fingerprint_libs(&self) -> bool {
        self.has_lib_matching(&["ja3", "ja4", "fingerprint"])
    }

    fn imports_ech_libraries(&self) -> bool {
        self.has_lib_matching(&["ech", "boringssl", "openssl"])
    }

    fn imports_noise_libraries(&self) -> bool {
        self.has_lib_matching(&["noise", "snow", "cacophony"])
    }

    fn imports_h2_libraries(&self) -> bool {
        self.has_lib_matching(&["h2", "http2", "hyper"])
    }

    fn imports_h3_libraries(&self) -> bool {
        self.has_lib_matching(&["h3", "http3", "quiche"])
    }

    fn imports_scion_libraries(&self) -> bool {
        self.has_lib_matching(&["scion", "snet", "dispatcher"])
    }

    fn imports_dht_libraries(&self) -> bool {
        self.has_lib_matching(&["dht", "kademlia", "libp2p"])
    }

    fn imports_mdns_libraries(&self) -> bool {
        self.has_lib_matching(&["mdns", "avahi", "bonjour"])
    }

    fn imports_bluetooth_libraries(&self) -> bool {
        self.has_lib_matching(&["bluetooth", "bluez", "ble"])
    }

    fn imports_nym_libraries(&self) -> bool {
        self.has_lib_matching(&["nym", "mixnet", "sphinx"])
    }

    fn imports_cashu_libraries(&self) -> bool {
        self.has_lib_matching(&["cashu", "ecash", "blinded"])
    }

    fn imports_lightning_libraries(&self) -> bool {
        self.has_lib_matching(&["lightning", "lnd", "bolt"])
    }

    fn imports_masque_libraries(&self) -> bool {
        self.has_lib_matching(&["masque", "connect-udp"])
    }

    fn has_lib_matching(&self, patterns: &[&str]) -> bool {
        self.needed_libs.iter()
            .chain(self.dynamic_deps.iter())
            .any(|lib| patterns.iter().any(|&pattern| lib.to_lowercase().contains(pattern)))
    }
}

// Protocol Support Structures
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HTXProtocolSupport {
    pub has_implementation: bool,
    pub supports_tcp_443: bool,
    pub supports_quic_443: bool,
    pub has_origin_mirroring: bool,
    pub has_ech_support: bool,
    pub detected_functions: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccessTicketSupport {
    pub has_ticket_system: bool,
    pub supports_carrier_negotiation: bool,
    pub supported_carriers: Vec<String>,
    pub has_replay_protection: bool,
    pub has_rate_limiting: bool,
    pub supports_x25519_exchange: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NoiseProtocolSupport {
    pub implements_noise_xk: bool,
    pub has_key_separation: bool,
    pub supports_rekeying: bool,
    pub has_nonce_management: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HTTPEmulationSupport {
    pub supports_http2: bool,
    pub supports_http3: bool,
    pub has_adaptive_cadence: bool,
    pub has_priority_frames: bool,
    pub has_padding: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SCIONBridgingSupport {
    pub has_scion_support: bool,
    pub has_gateway_functionality: bool,
    pub has_transition_control: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BetanetProtocolSupport {
    pub supported_protocols: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BootstrapSupport {
    pub has_rendezvous_system: bool,
    pub has_beacon_set: bool,
    pub has_proof_of_work: bool,
    pub supports_mdns: bool,
    pub supports_bluetooth: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MixnodeSupport {
    pub implements_nym_integration: bool,
    pub uses_beacon_set_randomness: bool,
    pub has_per_stream_entropy: bool,
    pub uses_vrf_selection: bool,
    pub ensures_path_diversity: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AliasLedgerSupport {
    pub has_alias_system: bool,
    pub implements_2of3_finality: bool,
    pub supported_chains: Vec<String>,
    pub has_emergency_advance: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CashuSupport {
    pub has_cashu_implementation: bool,
    pub supports_128b_vouchers: bool,
    pub has_lightning_settlement: bool,
    pub has_keyset_management: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GovernanceSupport {
    pub has_governance_system: bool,
    pub implements_voting_power: bool,
    pub has_uptime_scoring: bool,
    pub has_as_concentration_caps: bool,
    pub implements_quorum_requirements: bool,
    pub ensures_partition_safety: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnticorrelationSupport {
    pub has_fallback_mechanisms: bool,
    pub supports_udp_tcp_fallback: bool,
    pub implements_cover_connections: bool,
    pub has_randomized_timing: bool,
    pub supports_masque: bool,
}

pub trait ProtocolSupport {
    fn compliance_score(&self) -> f32;
    fn is_compliant(&self) -> bool {
        self.compliance_score() >= 0.8
    }
}

impl ProtocolSupport for HTXProtocolSupport {
    fn compliance_score(&self) -> f32 {
        let mut score = 0.0;
        if self.has_implementation { score += 0.3; }
        if self.supports_tcp_443 { score += 0.2; }
        if self.supports_quic_443 { score += 0.2; }
        if self.has_origin_mirroring { score += 0.15; }
        if self.has_ech_support { score += 0.15; }
        score
    }
}

// Implement ProtocolSupport for other support structures...
impl ProtocolSupport for AccessTicketSupport {
    fn compliance_score(&self) -> f32 {
        let mut score = 0.0;
        if self.has_ticket_system { score += 0.3; }
        if self.supports_carrier_negotiation { score += 0.2; }
        if self.has_replay_protection { score += 0.2; }
        if self.has_rate_limiting { score += 0.15; }
        if self.supports_x25519_exchange { score += 0.15; }
        score
    }
}

impl ProtocolSupport for BetanetProtocolSupport {
    fn compliance_score(&self) -> f32 {
        let required = vec!["/betanet/htx/1.1.0", "/betanet/htxquic/1.1.0"];
        let found = required.iter().filter(|&p| self.supported_protocols.contains(&p.to_string())).count();
        found as f32 / required.len() as f32
    }
}
