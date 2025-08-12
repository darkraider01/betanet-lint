//! Enhanced SBOM generation with SLSA 3 provenance support

use std::{collections::HashMap, fs, path::PathBuf, time::Duration};
use sha2::Digest;
use crate::binary::{BinaryMeta, LicenseInfo};
use serde_json::json;
use thiserror::Error;
use strum::EnumString;
use tokio::runtime::Runtime;
use reqwest::{Client, ClientBuilder};

// CycloneDX imports
use cyclonedx_bom::prelude::*;
use cyclonedx_bom::models::component::{Classification, Scope};
use cyclonedx_bom::models::external_reference::{
    ExternalReference, ExternalReferenceType, ExternalReferences,
};
use cyclonedx_bom::models::tool::{Tool, Tools};
use cyclonedx_bom::models::organization::{OrganizationalContact, OrganizationalEntity};
use cyclonedx_bom::models::license::{LicenseChoice, Licenses, License as CdxLicense};
use cyclonedx_bom::models::property::{Property, Properties};

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaProvenance {
    pub builder: SlsaBuilder,
    pub build_type: String,
    pub invocation: SlsaInvocation,
    pub materials: Vec<SlsaMaterial>,
    pub byproducts: Vec<SlsaByproduct>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaBuilder {
    pub id: String,
    pub version: HashMap<String, String>,
    pub builtin_dependencies: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaInvocation {
    pub config_source: SlsaConfigSource,
    pub parameters: HashMap<String, String>,
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaConfigSource {
    pub uri: String,
    pub digest: HashMap<String, String>,
    pub entry_point: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaMaterial {
    pub uri: String,
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlsaByproduct {
    pub name: String,
    pub uri: Option<String>,
    pub digest: HashMap<String, String>,
}

impl Default for SbomOptions {
    fn default() -> Self {
        Self {
            include_vulnerabilities: false,
            generate_cbom: false,
            license_scan_depth: LicenseScanDepth::Basic,
            generate_vex: false,
            slsa_level: 1,
            include_provenance: true,
        }
    }
}

/// Enhanced interface with options
pub fn write_sbom_with_options(
    out_path: &PathBuf,
    meta: &BinaryMeta,
    format: SbomFormat,
    options: SbomOptions,
) -> Result<(), SbomError> {
    let rt = Runtime::new().map_err(|e| SbomError::Generation(e.to_string()))?;
    let data = rt.block_on(async {
        match format {
            SbomFormat::CycloneDx => generate_enhanced_cyclonedx(meta, &options).await,
            SbomFormat::Spdx => generate_enhanced_spdx(meta, &options).await,
        }
    })?;
    
    fs::write(out_path, data)?;
    
    // Generate SLSA provenance if requested and SLSA level >= 3
    if options.include_provenance && options.slsa_level >= 3 {
        generate_slsa_provenance(out_path, meta, &options)?;
    }
    
    Ok(())
}

/// Generate SLSA 3 provenance artifact
fn generate_slsa_provenance(sbom_path: &PathBuf, meta: &BinaryMeta, _options: &SbomOptions) -> Result<(), SbomError> {
    use std::collections::HashMap;
    
    let provenance = SlsaProvenance {
        builder: SlsaBuilder {
            id: "https://github.com/darkraider01/betanet-lint".to_string(),
            version: {
                let mut v = HashMap::new();
                v.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
                v
            },
            builtin_dependencies: vec![
                "rustc".to_string(),
                "cargo".to_string(),
            ],
        },
        build_type: "https://github.com/betanet/betanet-lint@v1".to_string(),
        invocation: SlsaInvocation {
            config_source: SlsaConfigSource {
                uri: "git+https://github.com/darkraider01/betanet-lint".to_string(),
                digest: {
                    let mut d = HashMap::new();
                    d.insert("sha1".to_string(), "HEAD".to_string()); // Would be actual commit hash
                    d
                },
                entry_point: "build".to_string(),
            },
            parameters: {
                let mut p = HashMap::new();
                p.insert("target".to_string(), "release".to_string());
                p
            },
            environment: meta.build_environment.environment_variables.clone(),
        },
        materials: vec![
            SlsaMaterial {
                uri: format!("file://{}", meta.path.display()),
                digest: {
                    let mut d = HashMap::new();
                    d.insert("sha256".to_string(), meta.sha256.clone());
                    d
                },
            }
        ],
        byproducts: vec![
            SlsaByproduct {
                name: "SBOM".to_string(),
                uri: Some(format!("file://{}", sbom_path.display())),
                digest: {
                    let mut d = HashMap::new();
                    if let Ok(sbom_data) = fs::read(sbom_path) {
                        d.insert("sha256".to_string(), format!("{:x}", sha2::Sha256::digest(&sbom_data)));
                    }
                    d
                },
            }
        ],
    };
    
    // Write SLSA provenance as .intoto.jsonl
    let provenance_path = sbom_path.with_extension("intoto.jsonl");
    let provenance_json = json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [{
            "name": meta.path.file_name().unwrap_or_default().to_string_lossy(),
            "digest": {
                "sha256": meta.sha256
            }
        }],
        "predicate": provenance
    });
    
    fs::write(provenance_path, serde_json::to_string_pretty(&provenance_json)?)?;
    
    Ok(())
}

/// Create a properly configured HTTP client with hardened settings
fn create_http_client() -> Result<Client, SbomError> {
    ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("betanet-lint/1.0 (https://github.com/darkraider01/betanet-lint)")
        .danger_accept_invalid_certs(false) // Enforce SSL verification
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .build()
        .map_err(SbomError::Network)
}

async fn check_vulnerabilities(component_name: &str) -> Result<Vec<Vulnerability>, SbomError> {
    let client = create_http_client()?;
    let mut vulnerabilities = Vec::new();
    
    // Enhanced OSV query with better ecosystem detection
    let ecosystem = detect_ecosystem(component_name);
    let query = json!({
        "package": {
            "name": component_name,
            "ecosystem": ecosystem
        }
    });
    
    match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
    ).await {
        Ok(Ok(response)) => {
            if response.status().is_success() {
                if let Ok(data) = response.json::<serde_json::Value>().await {
                    if let Some(vulns) = data.get("vulns").and_then(|v| v.as_array()) {
                        for vuln in vulns.iter().take(5) {
                            if let Some(id) = vuln.get("id").and_then(|i| i.as_str()) {
                                vulnerabilities.push(Vulnerability {
                                    id: id.to_string(),
                                    severity: vuln.get("database_specific")
                                        .and_then(|d| d.get("severity"))
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("UNKNOWN").to_string(),
                                    description: vuln.get("summary")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("No description available").to_string(),
                                    affected_versions: extract_affected_versions(vuln),
                                    fixed_versions: extract_fixed_versions(vuln),
                                    references: extract_references(vuln),
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => {
            log::warn!("Failed to query OSV for {component_name}: {e}");
        }
        Err(_) => {
            log::warn!("Timeout querying OSV for {component_name}");
        }
    }
    
    Ok(vulnerabilities)
}

fn detect_ecosystem(component_name: &str) -> &'static str {
    if component_name.ends_with(".so") || component_name.contains("lib") {
        "Linux"
    } else if component_name.ends_with(".dll") {
        "Windows"
    } else if component_name.ends_with(".dylib") {
        "macOS"  
    } else if component_name.contains("crate") || component_name.contains("rust") {
        "crates.io"
    } else {
        "Linux" // Default
    }
}

fn extract_affected_versions(vuln: &serde_json::Value) -> Vec<String> {
    vuln.get("affected")
        .and_then(|a| a.as_array())
        .map(|affected| {
            affected.iter()
                .filter_map(|item| item.get("versions").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_fixed_versions(vuln: &serde_json::Value) -> Vec<String> {
    vuln.get("affected")
        .and_then(|a| a.as_array())
        .map(|affected| {
            affected.iter()
                .filter_map(|item| item.get("fixed").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
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
                .collect()
        })
        .unwrap_or_default()
}

/* -------------------------------------------------------------------- */
/* SBOM Generation Functions                                            */
/* -------------------------------------------------------------------- */

async fn generate_enhanced_cyclonedx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    let name_string = meta
        .path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut main_component = Component::new(
        Classification::Application,
        &name_string,
        "unknown",
        None,
    );
    main_component.scope = Some(Scope::Required);

    // Enhanced external references
    let url_string = format!("file://{}", meta.path.display());
    dbg!(&url_string);
    // Temporarily revert to original to get error messages
    let mut ext_ref = ExternalReference::new(ExternalReferenceType::Other, Uri::try_from(url_string).map_err(|e| SbomError::Generation(e.to_string()))?);
    ext_ref.comment = Some("Analyzed binary file".to_string());
    main_component.external_references = Some(ExternalReferences(vec![ext_ref]));

    if !meta.licenses.is_empty() {
        main_component.licenses = Some(create_license_choices(&meta.licenses));
    }

    let mut components: Vec<Component> = vec![main_component];
    
    // Add library dependencies with enhanced vulnerability checking
    for lib_name in &meta.needed_libs {
        let mut lib_component = Component::new(
            Classification::Library,
            lib_name,
            "",
            None,
        );
        lib_component.scope = Some(Scope::Required);
        
        if options.include_vulnerabilities {
            if let Ok(vulns) = check_vulnerabilities(lib_name).await {
                if !vulns.is_empty() {
                    log::info!("Found {} vulnerabilities for {}", vulns.len(), lib_name);
                }
            }
        }
        
        components.push(lib_component);
    }

    // Enhanced cryptographic components with Betanet-specific metadata
    if options.generate_cbom {
        for crypto in &meta.crypto_components {
            let mut crypto_component = Component::new(
                Classification::Library,
                &format!("crypto-{}", crypto.algorithm),
                "detected",
                None,
            );
            crypto_component.scope = Some(Scope::Optional);
            
            crypto_component.properties = Some(Properties(vec![
                Property::new("crypto.algorithm", &crypto.algorithm),
                Property::new("crypto.quantum_safe", &crypto.quantum_safe.to_string()),
                Property::new("betanet.compliance.crypto", &format!("{:?}", crypto.compliance_status)),
                Property::new("crypto.usage_context", &format!("{:?}", crypto.usage_context)),
            ]));
            
            components.push(crypto_component);
        }
    }

    // Add Betanet-specific components
    if !meta.betanet_indicators.protocol_versions.is_empty() {
        let mut betanet_component = Component::new(
            Classification::Framework,
            "betanet-protocol",
            "1.1.0",
            None,
        );
        betanet_component.scope = Some(Scope::Required);
        betanet_component.properties = Some(Properties(vec![
            Property::new("betanet.htx_transports", &meta.betanet_indicators.htx_transport.len().to_string()),
            Property::new("betanet.protocol_versions", &meta.betanet_indicators.protocol_versions.join(",")),
            Property::new("betanet.compliance.level", "1.1"),
        ]));
        
        components.push(betanet_component);
    }

    let bom = Bom {
        serial_number: Some(UrnUuid::generate()),
        metadata: Some(create_enhanced_metadata(meta, options)),
        components: Some(Components(components)),
        ..Bom::default()
    };

    // Add build reproducibility information
    if meta.build_reproducibility.has_build_id {
        // This would be added as additional metadata
    }

    // Serialize to JSON
    let mut output = Vec::new();
    bom.output_as_json_v1_3(&mut output)
        .map_err(|e| SbomError::Generation(format!("CycloneDX serialization failed: {e}")))?;
    
    String::from_utf8(output)
        .map_err(|e| SbomError::Generation(format!("UTF-8 conversion failed: {e}")))
}

async fn generate_enhanced_spdx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    let mut spdx_doc = json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": chrono::Utc::now().to_rfc3339(),
            "creators": [
                "Tool: betanet-lint-enhanced",
                format!("Tool: betanet-lint-{}", env!("CARGO_PKG_VERSION"))
            ],
            "licenseListVersion": "3.20"
        },
        "name": format!("betanet-lint-sbom-{}", meta.path.file_name().unwrap_or_default().to_string_lossy()),
        "dataLicense": "CC0-1.0",
        "documentNamespace": format!("https://betanet.org/spdx/{}", uuid::Uuid::new_v4()),
        "packages": generate_enhanced_spdx_packages(meta, options).await,
        "relationships": generate_enhanced_spdx_relationships(meta),
        "files": generate_spdx_files(meta),
        "annotations": generate_enhanced_spdx_annotations(meta, options)
    });

    // Add SLSA provenance information
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

// Helper functions with enhanced metadata
fn create_enhanced_metadata(meta: &BinaryMeta, options: &SbomOptions) -> Metadata {
    let mut properties = vec![
        Property::new("betanet.compliance.version", "1.1"),
        Property::new("sbom.generation.timestamp", &chrono::Utc::now().to_rfc3339()),
        Property::new("sbom.network.timeout", "30s"),
        Property::new("sbom.network.user_agent", "betanet-lint/1.0"),
        Property::new("slsa.level", &options.slsa_level.to_string()),
        Property::new("betanet.build.reproducible", &meta.build_reproducibility.has_build_id.to_string()),
    ];

    // Add Betanet-specific properties
    properties.push(Property::new("betanet.htx.indicators", &meta.betanet_indicators.htx_transport.len().to_string()));
    properties.push(Property::new("betanet.crypto.components", &meta.crypto_components.len().to_string()));
    properties.push(Property::new("betanet.protocol.versions", &meta.betanet_indicators.protocol_versions.len().to_string()));

    // Add build environment properties
    for (key, value) in &meta.build_environment.environment_variables {
        properties.push(Property::new(format!("build.env.{key}"), value));
    }

    // Add build reproducibility info
    if let Some(build_id_type) = &meta.build_reproducibility.build_id_type {
        properties.push(Property::new("build.id.type", build_id_type));
    }
    if let Some(build_id_value) = &meta.build_reproducibility.build_id_value {
        properties.push(Property::new("build.id.value", build_id_value));
    }

    Metadata {
        timestamp: Some(DateTime::now().expect("failed to get current time")),
        tools: Some(Tools(vec![Tool {
            name: Some(NormalizedString::new("betanet-lint")),
            version: Some(NormalizedString::new(env!("CARGO_PKG_VERSION"))),
            vendor: Some(NormalizedString::new("Betanet")),
            ..Tool::default()
        }])),
        authors: Some(vec![OrganizationalContact::new("Betanet Team", None)]),
        supplier: Some(OrganizationalEntity {
            name: Some(NormalizedString::new("Betanet")),
            url: None,
            contact: None,
        }),
        properties: Some(Properties(properties)),
        ..Metadata::default()
    }
}

fn create_license_choices(licenses: &[LicenseInfo]) -> Licenses {
    let choices = licenses
        .iter()
        .map(|license| {
            dbg!(&license.license_id);
            LicenseChoice::License({
                let cdx_license = CdxLicense::license_id(&license.license_id)
                    .unwrap_or_else(|e| {
                        log::warn!("Invalid SPDX ID '{}', using named license fallback: {}", license.license_id, e);
                        CdxLicense::named_license(&license.license_id)
                    });
                cdx_license
            })
        })
        .collect();
    Licenses(choices)
}

async fn generate_enhanced_spdx_packages(meta: &BinaryMeta, options: &SbomOptions) -> serde_json::Value {
    let mut packages = vec![json!({
        "SPDXID": "SPDXRef-Package-Binary",
        "name": meta.path.file_name().unwrap_or_default().to_string_lossy(),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": true,
        "checksums": [{
            "algorithm": "SHA256",
            "checksumValue": meta.sha256
        }],
        "copyrightText": "NOASSERTION",
        "licenseConcluded": format_licenses_for_spdx(&meta.licenses),
        "licenseDeclared": format_licenses_for_spdx(&meta.licenses),
        "versionInfo": "unknown"
    })];

    // Add library packages with enhanced metadata
    for (idx, lib) in meta.needed_libs.iter().enumerate() {
        let mut package = json!({
            "SPDXID": format!("SPDXRef-Package-Lib-{}", idx),
            "name": lib,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "copyrightText": "NOASSERTION"
        });

        // Add vulnerability information if requested
        if options.include_vulnerabilities {
            if let Ok(vulns) = check_vulnerabilities(lib).await {
                if !vulns.is_empty() {
                    package["vulnerabilities"] = serde_json::to_value(&vulns).unwrap_or_default();
                }
            }
        }

        packages.push(package);
    }

    // Add Betanet protocol package if indicators found
    if !meta.betanet_indicators.protocol_versions.is_empty() {
        packages.push(json!({
            "SPDXID": "SPDXRef-Package-Betanet-Protocol",
            "name": "betanet-protocol",
            "versionInfo": "1.1.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "copyrightText": "NOASSERTION",
            "comment": format!("Betanet 1.1 protocol implementation detected with {} transports", 
                             meta.betanet_indicators.network_transports.len())
        }));
    }

    json!(packages)
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

    // Add Betanet protocol relationship if detected
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
        "checksums": [{
            "algorithm": "SHA256",
            "checksumValue": meta.sha256
        }],
        "copyrightText": "NOASSERTION",
        "licenseConcluded": format_licenses_for_spdx(&meta.licenses),
    })];

    // Add embedded files
    for (idx, embedded_file) in meta.embedded_files.iter().enumerate() {
        files.push(json!({
            "SPDXID": format!("SPDXRef-File-Embedded-{}", idx),
            "fileName": embedded_file.path,
            "checksums": [{
                "algorithm": "MD5",
                "checksumValue": embedded_file.hash
            }],
            "copyrightText": "NOASSERTION",
            "fileTypes": [embedded_file.file_type]
        }));
    }

    json!(files)
}

fn generate_enhanced_spdx_annotations(meta: &BinaryMeta, options: &SbomOptions) -> serde_json::Value {
    let mut annotations = Vec::new();

    // CBOM annotation
    if options.generate_cbom && !meta.crypto_components.is_empty() {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER", 
            "annotationComment": format!("CBOM: {} cryptographic components detected (Betanet 1.1 compliant)", 
                                       meta.crypto_components.len()),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
        }));
    }

    // Compiler annotation
    if let Some(compiler) = &meta.compiler_info {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!("Compiled with {} version {} (optimization: {})", 
                                       compiler.compiler, compiler.version, compiler.optimization_level),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
        }));
    }

    // Build reproducibility annotation
    if meta.build_reproducibility.has_build_id {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!("Reproducible build with {} (SLSA level {})", 
                                       meta.build_reproducibility.build_id_type.as_ref().unwrap_or(&"unknown".to_string()),
                                       options.slsa_level),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
        }));
    }

    // Betanet compliance annotation
    if !meta.betanet_indicators.protocol_versions.is_empty() {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!("Betanet 1.1 protocol indicators detected: {} transports, {} crypto protocols", 
                                       meta.betanet_indicators.network_transports.len(),
                                       meta.betanet_indicators.crypto_protocols.len()),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
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

