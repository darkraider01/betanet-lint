//! Enhanced SBOM generation with SLSA 3 provenance support
//!
//! This module provides secure, timeout-protected SBOM generation with proper
//! vulnerability scanning and cryptographic bill of materials (CBOM) support.

use std::{fs, path::PathBuf, time::Duration};
use crate::binary::{BinaryMeta, LicenseInfo};
use crate::slsa::SLSAGenerator;
use serde_json::json;
use thiserror::Error;
use strum::EnumString;
use reqwest::{Client, ClientBuilder};

#[derive(Debug, EnumString, Clone, Copy)]
pub enum SbomFormat {
    #[strum(serialize = "cyclonedx")]
    CycloneDx,
    #[strum(serialize = "spdx")]
    Spdx,
}

#[derive(Debug, Clone)]
pub struct SbomOptions {
    pub include_vulnerabilities: bool,
    pub generate_cbom: bool,
    pub license_scan_depth: LicenseScanDepth,
    pub generate_vex: bool,
    pub slsa_level: u8,
    pub include_provenance: bool,
    pub offline_mode: bool,
}

#[derive(Debug, Clone)]
pub enum LicenseScanDepth {
    Basic,
    Comprehensive,
    Deep,
}

#[derive(Error, Debug)]
pub enum SbomError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SBOM generation error: {0}")]
    Generation(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Timeout error: {0}")]
    Timeout(String),
    #[error("SLSA provenance error: {0}")]
    SlsaProvenance(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: String,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
}

impl Default for SbomOptions {
    fn default() -> Self {
        Self {
            include_vulnerabilities: false,
            generate_cbom: false,
            license_scan_depth: LicenseScanDepth::Basic,
            generate_vex: false,
            slsa_level: 3, // Default to SLSA Level 3
            include_provenance: true,
            offline_mode: false,
        }
    }
}

/// Enhanced SBOM generation with security hardening
pub async fn write_sbom_with_options(
    out_path: &PathBuf,
    meta: &BinaryMeta,
    format: SbomFormat,
    options: SbomOptions,
) -> Result<(), SbomError> {
    log::info!("Generating enhanced SBOM in {:?} format", format);

    let data = match format {
        SbomFormat::CycloneDx => generate_enhanced_cyclonedx(meta, &options).await,
        SbomFormat::Spdx => generate_enhanced_spdx(meta, &options).await,
    }?;

    fs::write(out_path, data)?;
    log::info!("SBOM written to: {}", out_path.display());

    // Generate SLSA provenance if requested and SLSA level >= 3
    if options.include_provenance && options.slsa_level >= 3 {
        let slsa_generator = SLSAGenerator::new();
        let provenance = slsa_generator
            .generate_provenance(meta, Some(out_path))
            .map_err(|e| SbomError::SlsaProvenance(e.to_string()))?;

        let provenance_path = out_path.with_extension("intoto.jsonl");
        slsa_generator
            .write_provenance_file(&provenance, &provenance_path)
            .map_err(|e| SbomError::SlsaProvenance(e.to_string()))?;

        log::info!(
            "SLSA Level {} provenance written to: {}",
            options.slsa_level,
            provenance_path.display()
        );
    }

    Ok(())
}

/// Create a properly configured HTTP client with security hardening
///
/// This addresses the original security vulnerability of uncontrolled network requests
fn create_hardened_http_client() -> Result<Client, SbomError> {
    log::debug!("Creating hardened HTTP client with timeouts and security controls");

    ClientBuilder::new()
        // Security: Set reasonable timeouts to prevent hanging CI/CD
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        // Security: Proper User-Agent identification
        .user_agent(format!(
            "betanet-lint/{} (https://github.com/darkraider01/betanet-lint)",
            env!("CARGO_PKG_VERSION")
        ))
        // Security: Enforce SSL verification
        .danger_accept_invalid_certs(false)
        // Performance: Connection pooling limits
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        // Security: Limit redirects
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(SbomError::Network)
}

/// Secure vulnerability checking with proper timeout and error handling
async fn check_vulnerabilities_secure(component_name: &str) -> Result<Vec<Vulnerability>, SbomError> {
    log::debug!("Checking vulnerabilities for component: {}", component_name);

    let client = create_hardened_http_client()?;
    let mut vulnerabilities = Vec::new();

    // Enhanced OSV query with better ecosystem detection
    let ecosystem = detect_ecosystem(component_name);
    let query = json!({
        "package": {
            "name": component_name,
            "ecosystem": ecosystem
        }
    });

    // Security: Use timeout to prevent hanging operations
    match tokio::time::timeout(
        Duration::from_secs(15), // Strict timeout
        client.post("https://api.osv.dev/v1/query").json(&query).send(),
    )
    .await
    {
        Ok(Ok(response)) => {
            if response.status().is_success() {
                if let Ok(data) = response.json::<serde_json::Value>().await {
                    if let Some(vulns) = data.get("vulns").and_then(|v| v.as_array()) {
                        // Security: Limit number of vulnerabilities processed
                        for vuln in vulns.iter().take(10) {
                            if let Some(id) = vuln.get("id").and_then(|i| i.as_str()) {
                                vulnerabilities.push(Vulnerability {
                                    id: id.to_string(),
                                    severity: vuln
                                        .get("database_specific")
                                        .and_then(|d| d.get("severity"))
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("UNKNOWN")
                                        .to_string(),
                                    description: vuln
                                        .get("summary")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("No description available")
                                        .chars()
                                        .take(500)
                                        .collect(),
                                    affected_versions: extract_affected_versions(vuln),
                                    fixed_versions: extract_fixed_versions(vuln),
                                    references: extract_references(vuln),
                                });
                            }
                        }
                    }
                }
            } else {
                log::warn!(
                    "OSV API returned status: {} for component: {}",
                    response.status(),
                    component_name
                );
            }
        }
        Ok(Err(e)) => {
            log::warn!("Network error querying OSV for {}: {}", component_name, e);
        }
        Err(_) => {
            log::warn!("Timeout querying OSV for component: {}", component_name);
            return Err(SbomError::Timeout(format!("OSV query timeout for {}", component_name)));
        }
    }

    log::debug!("Found {} vulnerabilities for {}", vulnerabilities.len(), component_name);
    Ok(vulnerabilities)
}

fn detect_ecosystem(component_name: &str) -> &'static str {
    if component_name.ends_with(".dylib") {
        "macOS"
    } else if component_name.ends_with(".dll") {
        "Windows"
    } else if component_name.ends_with(".so") {
        "Linux"
    } else if component_name.contains("crate") || component_name.contains("rust") {
        "crates.io"
    } else if component_name.contains("lib") {
        "Linux"
    } else {
        "Linux" // Default
    }
}

fn extract_affected_versions(vuln: &serde_json::Value) -> Vec<String> {
    vuln.get("affected")
        .and_then(|a| a.as_array())
        .map(|affected| {
            affected
                .iter()
                .filter_map(|item| item.get("versions").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .take(5)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_fixed_versions(vuln: &serde_json::Value) -> Vec<String> {
    vuln.get("affected")
        .and_then(|a| a.as_array())
        .map(|affected| {
            affected
                .iter()
                .filter_map(|item| item.get("fixed").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .take(5)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_references(vuln: &serde_json::Value) -> Vec<String> {
    vuln.get("references")
        .and_then(|r| r.as_array())
        .map(|refs| {
            refs.iter()
                .filter_map(|item| item.get("url").and_then(|u| u.as_str()))
                .map(|s| s.to_string())
                .take(3)
                .collect()
        })
        .unwrap_or_default()
}

/*
 * ════════════════════════════════════════════════════════════════════════════
 * ENHANCED SBOM GENERATION FUNCTIONS
 * ════════════════════════════════════════════════════════════════════════════
 */

async fn generate_enhanced_cyclonedx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    // Minimal CycloneDX JSON placeholder to interoperate with existing tooling.
    // Replace with full CycloneDX generation if needed.
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "tools": [{ "vendor": "Betanet Team", "name": "betanet-lint", "version": env!("CARGO_PKG_VERSION") }],
            "properties": [
                { "name": "slsa.level", "value": options.slsa_level.to_string() },
                { "name": "sbom.offline_mode", "value": options.offline_mode.to_string() }
            ]
        },
        "components": [{
            "type": "application",
            "name": meta.path.file_name().unwrap_or_default().to_string_lossy(),
            "version": "unknown"
        }]
    });
    serde_json::to_string_pretty(&doc).map_err(SbomError::Json)
}

async fn generate_enhanced_spdx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    log::info!("Generating SPDX SBOM with enhanced metadata");

    let mut spdx_doc = json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": chrono::Utc::now().to_rfc3339(),
            "creators": [
                format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION")),
                "Organization: Betanet Team"
            ],
            "licenseListVersion": "3.21"
        },
        "name": format!("betanet-compliance-sbom-{}", meta.path.file_name().unwrap_or_default().to_string_lossy()),
        "dataLicense": "CC0-1.0",
        "documentNamespace": format!("https://betanet.org/spdx/{}", uuid::Uuid::new_v4()),
        "packages": generate_enhanced_spdx_packages(meta, options).await?,
        "relationships": generate_enhanced_spdx_relationships(meta),
        "files": generate_spdx_files(meta),
        "annotations": generate_enhanced_spdx_annotations(meta, options)
    });

    if options.include_provenance && options.slsa_level >= 3 {
        spdx_doc["externalDocumentRefs"] = json!([{
            "externalDocumentId": "DocumentRef-SLSA-Provenance",
            "document": format!("{}.intoto.jsonl", meta.path.file_name().unwrap_or_default().to_string_lossy()),
            "checksum": {
                "algorithm": "SHA256",
                "checksumValue": "placeholder-for-provenance-hash"
            }
        }]);
    }

    serde_json::to_string_pretty(&spdx_doc).map_err(SbomError::Json)
}

async fn generate_enhanced_spdx_packages(meta: &BinaryMeta, options: &SbomOptions) -> Result<serde_json::Value, SbomError> {
    let mut packages = vec![json!({
        "SPDXID": "SPDXRef-Package-Binary",
        "name": meta.path.file_name().unwrap_or_default().to_string_lossy(),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": true,
        "checksums": [{ "algorithm": "SHA256", "checksumValue": meta.sha256 }],
        "copyrightText": "NOASSERTION",
        "licenseConcluded": format_licenses_for_spdx(&meta.licenses),
        "licenseDeclared": format_licenses_for_spdx(&meta.licenses),
        "versionInfo": "unknown"
    })];

    for (idx, lib) in meta.needed_libs.iter().enumerate() {
        let mut package = json!({
            "SPDXID": format!("SPDXRef-Package-Lib-{}", idx),
            "name": lib,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "copyrightText": "NOASSERTION"
        });

        if options.include_vulnerabilities && !options.offline_mode {
            match check_vulnerabilities_secure(lib).await {
                Ok(vulns) => {
                    if !vulns.is_empty() {
                        package["vulnerabilities"] = serde_json::to_value(&vulns).unwrap_or_default();
                    }
                }
                Err(e) => log::warn!("Failed to get vulnerabilities for {}: {}", lib, e),
            }
        }

        packages.push(package);
    }

    if !meta.betanet_indicators.protocol_versions.is_empty() {
        packages.push(json!({
            "SPDXID": "SPDXRef-Package-Betanet-Protocol",
            "name": "betanet-protocol",
            "versionInfo": "1.1.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "comment": format!(
                "Betanet 1.1 protocol implementation detected with {} transports",
                meta.betanet_indicators.network_transports.len()
            )
        }));
    }

    Ok(json!(packages))
}

fn generate_enhanced_spdx_relationships(meta: &BinaryMeta) -> serde_json::Value {
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-Binary"
    })];

    for idx in 0..meta.needed_libs.len() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": format!("SPDXRef-Package-Lib-{}", idx)
        }));
    }

    if !meta.betanet_indicators.protocol_versions.is_empty() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-Package-Betanet-Protocol"
        }));
    }

    json!(relationships)
}

fn generate_spdx_files(meta: &BinaryMeta) -> serde_json::Value {
    let mut files = vec![json!({
        "SPDXID": "SPDXRef-File-Binary",
        "fileName": meta.path.to_string_lossy(),
        "checksums": [{ "algorithm": "SHA256", "checksumValue": meta.sha256 }],
        "copyrightText": "NOASSERTION",
        "licenseConcluded": format_licenses_for_spdx(&meta.licenses)
    })];

    for (idx, embedded_file) in meta.embedded_files.iter().take(10).enumerate() {
        files.push(json!({
            "SPDXID": format!("SPDXRef-File-Embedded-{}", idx),
            "fileName": embedded_file.path,
            "checksums": [{ "algorithm": "SHA256", "checksumValue": embedded_file.hash }],
            "copyrightText": "NOASSERTION",
            "fileTypes": [embedded_file.file_type]
        }));
    }

    json!(files)
}

fn generate_enhanced_spdx_annotations(meta: &BinaryMeta, options: &SbomOptions) -> serde_json::Value {
    let mut annotations = Vec::new();

    if options.generate_cbom && !meta.crypto_components.is_empty() {
        let quantum_safe_count = meta.crypto_components.iter().filter(|c| c.quantum_safe).count();
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!(
                "CBOM: {} cryptographic components detected ({} quantum-safe, Betanet 1.1 compliant)",
                meta.crypto_components.len(),
                quantum_safe_count
            ),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION"))
        }));
    }

    if let Some(compiler) = &meta.compiler_info {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!(
                "Compiled with {} version {} (optimization: {}, target: {})",
                compiler.compiler,
                compiler.version,
                compiler.optimization_level,
                compiler.target_triple
            ),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION"))
        }));
    }

    if meta.build_reproducibility.has_build_id {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!(
                "Reproducible build with {} (SLSA level {}, {} deterministic indicators)",
                meta.build_reproducibility.build_id_type.as_ref().unwrap_or(&"unknown".to_string()),
                options.slsa_level,
                meta.build_reproducibility.deterministic_indicators.len()
            ),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION"))
        }));
    }

    if !meta.betanet_indicators.protocol_versions.is_empty() {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!(
                "Betanet 1.1 compliance: {} protocol versions, {} crypto protocols, {} transport methods",
                meta.betanet_indicators.protocol_versions.len(),
                meta.betanet_indicators.crypto_protocols.len(),
                meta.betanet_indicators.network_transports.len()
            ),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION"))
        }));
    }

    json!(annotations)
}

fn format_licenses_for_spdx(licenses: &[LicenseInfo]) -> String {
    if licenses.is_empty() {
        "NOASSERTION".to_string()
    } else if licenses.len() == 1 {
        licenses[0].license_id.clone()
    } else {
        let license_ids: Vec<String> = licenses.iter().map(|l| l.license_id.clone()).collect();
        format!("({})", license_ids.join(" OR "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::*;
    use std::collections::HashMap;

    fn create_test_meta() -> BinaryMeta {
        BinaryMeta {
            path: std::path::PathBuf::from("test_binary"),
            format: BinFormat::Elf,
            size_bytes: 1000,
            strings: vec!["test".to_string()],
            sha256: "abcd1234".to_string(),
            needed_libs: vec!["libtest.so".to_string()],
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
                htx_transport: vec![],
                protocol_versions: vec![],
                crypto_protocols: vec![],
                network_transports: vec![],
                p2p_protocols: vec![],
                governance_indicators: vec![],
            },
            build_reproducibility: BuildReproducibility {
                has_build_id: true,
                build_id_type: Some("GNU Build ID".to_string()),
                build_id_value: Some("deadbeef".to_string()),
                deterministic_indicators: vec![],
                timestamp_embedded: false,
            },
            imported_symbols: vec![],
            exported_symbols: vec![],
            section_names: vec![],
            dynamic_dependencies: vec![],
        }
    }

    #[test]
    fn test_hardened_client_creation() {
        let client = create_hardened_http_client();
        assert!(client.is_ok(), "Hardened HTTP client should be created successfully");
    }

    #[test]
    fn test_ecosystem_detection() {
        assert_eq!(detect_ecosystem("libtest.so"), "Linux");
        assert_eq!(detect_ecosystem("test.dll"), "Windows");
        assert_eq!(detect_ecosystem("libtest.dylib"), "macOS");
        assert_eq!(detect_ecosystem("rust-crate"), "crates.io");
    }
}
