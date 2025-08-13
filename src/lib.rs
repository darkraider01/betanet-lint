pub mod binary;
pub mod checks;
pub mod sbom;

pub use binary::BinaryMeta;
pub use checks::{CheckResult, run_all_checks, write_report_json};
pub use sbom::{SbomFormat, SbomOptions, LicenseScanDepth, write_sbom_with_options};

// Stubs for Betanet 1.1 compliance checks
// BN-11.1 HTX transport
pub fn betanet_htx_transport_init() {
    // Placeholder for HTX transport initialization
}

// BN-11.2 Access tickets
pub fn betanet_access_tickets_init() {
    // Placeholder for access ticket initialization
}

// BN-11.3 Noise XK
pub fn betanet_noise_xk_init() {
    // Placeholder for Noise XK initialization
}

// BN-11.4 HTTP emulation
pub fn betanet_http_emulation_init() {
    // Placeholder for HTTP emulation initialization
}

// BN-11.5 SCION bridging
pub fn betanet_scion_bridging_init() {
    // Placeholder for SCION bridging initialization
}

// BN-11.6 Betanet protocols
pub fn betanet_protocols_init() {
    // Placeholder for betanet protocols initialization
}

// BN-11.7 Bootstrap features
pub fn betanet_bootstrap_features_init() {
    // Placeholder for bootstrap features initialization
}

// BN-11.8 Mixnode selection
pub fn betanet_mixnode_selection_init() {
    // Placeholder for mixnode selection initialization
}

// BN-11.9 Alias ledger
pub fn betanet_alias_ledger_init() {
    // Placeholder for alias ledger initialization
}

// BN-11.10 Cashu
pub fn betanet_cashu_init() {
    // Placeholder for Cashu initialization
}

// BN-11.11 Governance
pub fn betanet_governance_init() {
    // Placeholder for governance initialization
}

// BN-11.12 Anti-correlation
pub fn betanet_anti_correlation_init() {
    // Placeholder for anti-correlation initialization
}

// BN-11.13 SLSA/provenance
pub fn betanet_slsa_provenance_init() {
    // Placeholder for SLSA/provenance initialization
}
