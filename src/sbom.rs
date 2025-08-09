//! Comprehensive SBOM generation with advanced features

use std::{fs, path::PathBuf};
use crate::binary::{BinaryMeta, LicenseInfo};
use serde_json::json;
use thiserror::Error;
use strum::EnumString;
use tokio::runtime::Runtime;
use reqwest::Client;

// CycloneDX imports
use cyclonedx_bom::prelude::*;
use cyclonedx_bom::models::component::{Classification, Scope};
use cyclonedx_bom::models::external_reference::{
    ExternalReference, ExternalReferenceType, ExternalReferences,
};
use cyclonedx_bom::models::tool::{Tool, Tools};
use cyclonedx_bom::models::organization::{OrganizationalContact, OrganizationalEntity};
use cyclonedx_bom::models::license::{LicenseChoice, Licenses};
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
}

#[derive(Debug, Clone)]
pub enum LicenseScanDepth {
    Basic,
    Comprehensive,
    Deep,
}

fn license_scan_depth_to_str(depth: &LicenseScanDepth) -> &'static str {
    match depth {
        LicenseScanDepth::Basic => "basic",
        LicenseScanDepth::Comprehensive => "comprehensive",
        LicenseScanDepth::Deep => "deep",
    }
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
pub struct VexStatement {
    pub vulnerability: String,
    pub products: Vec<String>,
    pub status: VexStatus,
    pub justification: Option<String>,
    pub response: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl Default for SbomOptions {
    fn default() -> Self {
        Self {
            include_vulnerabilities: false,
            generate_cbom: false,
            license_scan_depth: LicenseScanDepth::Basic,
            generate_vex: false,
            slsa_level: 1,
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
    Ok(())
}

/// Legacy interface for backward compatibility
#[allow(dead_code)]
pub fn write_sbom(
    out_path: &PathBuf,
    meta: &BinaryMeta,
    format: SbomFormat,
) -> Result<(), SbomError> {
    write_sbom_with_options(out_path, meta, format, SbomOptions::default())
}

/* -------------------------------------------------------------------- */
/*  Enhanced CycloneDX Generation                                       */
/* -------------------------------------------------------------------- */

async fn generate_enhanced_cyclonedx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    // Create the main component (the analyzed binary)
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

    // Add external references
    let url_string = format!("file://{}", meta.path.display());
    let uri = Uri::new(&url_string);
    let mut ext_ref = ExternalReference::new(ExternalReferenceType::Other, uri);
    ext_ref.comment = Some("Analyzed binary file".to_string());
    main_component.external_references = Some(ExternalReferences(vec![ext_ref]));

    // Add licenses if detected
    if !meta.licenses.is_empty() {
        main_component.licenses = Some(create_license_choices(&meta.licenses));
    }

    // Create dependency components
    let mut components: Vec<Component> = vec![main_component];
    
    // Add library dependencies
    for lib_name in &meta.needed_libs {
        let mut lib_component = Component::new(
            Classification::Library,
            lib_name,
            "",
            None,
        );
        lib_component.scope = Some(Scope::Required);

        components.push(lib_component);
    }

    // Add cryptographic components if CBOM requested
    if options.generate_cbom {
        for crypto in &meta.crypto_components {
            let mut crypto_component = Component::new(
                Classification::Library,
                &format!("crypto-{}", crypto.algorithm),
                "detected",
                None,
            );
            crypto_component.scope = Some(Scope::Optional);
            
            // Add crypto-specific properties
            crypto_component.properties = Some(Properties(vec![
                Property::new("crypto.algorithm", &crypto.algorithm),
                Property::new("crypto.quantum_safe", &crypto.quantum_safe.to_string()),
            ]));
            
            components.push(crypto_component);
        }
    }

    // Add static library components
    for static_lib in &meta.static_libraries {
        let mut static_component = Component::new(
            Classification::Library,
            &static_lib.name,
            "static",
            None,
        );
        static_component.scope = Some(Scope::Required);
        static_component.properties = Some(Properties(vec![
            Property::new("library.type", "static"),
            Property::new("library.checksum", &static_lib.checksum),
        ]));
        
        components.push(static_component);
    }

    // Create the BOM
    let mut bom = Bom::default();
    bom.serial_number = Some(UrnUuid::generate());
    
    // Enhanced metadata
    bom.metadata = Some(create_enhanced_metadata(meta, options));
    bom.components = Some(Components(components));

    // Add VEX statements if requested
    if options.generate_vex {
        // VEX would be added here in a real implementation
        // This requires additional CycloneDX extensions
    }

    // Serialize to JSON
    let mut output = Vec::new();
    bom.output_as_json_v1_5(&mut output)
        .map_err(|e| SbomError::Generation(format!("CycloneDX serialization failed: {}", e)))?;
    
    String::from_utf8(output)
        .map_err(|e| SbomError::Generation(format!("UTF-8 conversion failed: {}", e)))
}

fn create_enhanced_metadata(meta: &BinaryMeta, options: &SbomOptions) -> Metadata {
    let mut properties = vec![
        Property::new("betanet.compliance.version", "1.0"),
        Property::new(
            "betanet.analysis.depth",
            license_scan_depth_to_str(&options.license_scan_depth),
        ),
        Property::new("sbom.generation.timestamp", &chrono::Utc::now().to_rfc3339()),
        Property::new("sbom.options.vulnerabilities", &options.include_vulnerabilities.to_string()),
        Property::new("sbom.options.cbom", &options.generate_cbom.to_string()),
        Property::new("sbom.options.slsa_level", &options.slsa_level.to_string()),
        Property::new(
            "sbom.options.license_scan_depth",
            license_scan_depth_to_str(&options.license_scan_depth),
        ),
    ];

    // Add build environment properties
    for (key, value) in &meta.build_environment.environment_variables {
        properties.push(Property::new(&format!("build.env.{}", key), value));
    }

    // Add compiler information
    if let Some(compiler) = &meta.compiler_info {
        properties.push(Property::new("build.compiler.name", &compiler.compiler));
        properties.push(Property::new("build.compiler.version", &compiler.version));
    }

    Metadata {
        timestamp: Some(DateTime::now().expect("failed to get current time")),
        tools: Some(Tools::List(vec![Tool {
            name: Some(NormalizedString::new("betanet-lint")),
            version: Some(NormalizedString::new(env!("CARGO_PKG_VERSION"))),
            vendor: Some(NormalizedString::new("Betanet")),
            ..Tool::default()
        }])),
        authors: Some(vec![OrganizationalContact::new("Betanet Team", None)]),
        supplier: Some(OrganizationalEntity::new("Betanet")),
        properties: Some(Properties(properties)),
        ..Metadata::default()
    }
}

fn create_license_choices(licenses: &[LicenseInfo]) -> Licenses {
    let choices = licenses
        .iter()
        .map(|license| LicenseChoice::license(&license.license_id))
        .collect();
    Licenses(choices)
}

// Note: CycloneDX vulnerability modeling omitted in CycloneDX output for now.

/* -------------------------------------------------------------------- */
/*  Enhanced SPDX Generation                                            */
/* -------------------------------------------------------------------- */

async fn generate_enhanced_spdx(meta: &BinaryMeta, options: &SbomOptions) -> Result<String, SbomError> {
    let mut spdx_doc = json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": chrono::Utc::now().to_rfc3339(),
            "creators": ["Tool: betanet-lint-enhanced"],
            "licenseListVersion": "3.20"
        },
        "name": format!("betanet-lint-sbom-{}", meta.path.file_name().unwrap_or_default().to_string_lossy()),
        "dataLicense": "CC0-1.0",
        "documentNamespace": format!("https://betanet.org/spdx/{}", uuid::Uuid::new_v4()),
        "packages": generate_enhanced_spdx_packages(meta, options).await,
        "relationships": generate_enhanced_spdx_relationships(meta),
        "files": generate_spdx_files(meta),
    });

    // Add annotations for enhanced features
    if options.generate_cbom || options.include_vulnerabilities {
        spdx_doc["annotations"] = generate_spdx_annotations(meta, options);
    }

    serde_json::to_string_pretty(&spdx_doc).map_err(SbomError::Json)
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
                package["vulnerabilities"] = serde_json::to_value(&vulns).unwrap_or_default();
            }
        }

        packages.push(package);
    }

    // Add cryptographic components as packages if CBOM requested
    if options.generate_cbom {
        for (idx, crypto) in meta.crypto_components.iter().enumerate() {
            packages.push(json!({
                "SPDXID": format!("SPDXRef-Package-Crypto-{}", idx),
                "name": format!("crypto-{}", crypto.algorithm),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "copyrightText": "NOASSERTION",
                "comment": format!("Cryptographic component: {} (quantum_safe: {})", 
                                 crypto.algorithm, crypto.quantum_safe)
            }));
        }
    }

    json!(packages)
}

fn generate_enhanced_spdx_relationships(meta: &BinaryMeta) -> serde_json::Value {
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-Binary"
    })];

    // Add library dependency relationships
    for idx in 0..meta.needed_libs.len() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": format!("SPDXRef-Package-Lib-{}", idx)
        }));
    }

    // Add crypto component relationships
    for idx in 0..meta.crypto_components.len() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": format!("SPDXRef-Package-Crypto-{}", idx)
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

fn generate_spdx_annotations(meta: &BinaryMeta, options: &SbomOptions) -> serde_json::Value {
    let mut annotations = Vec::new();

    if options.generate_cbom {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER", 
            "annotationComment": format!("CBOM: {} cryptographic components detected", 
                                       meta.crypto_components.len()),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
        }));
    }

    if let Some(compiler) = &meta.compiler_info {
        annotations.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "annotationType": "OTHER",
            "annotationComment": format!("Compiled with {} version {}", 
                                       compiler.compiler, compiler.version),
            "annotationDate": chrono::Utc::now().to_rfc3339(),
            "annotator": "Tool: betanet-lint"
        }));
    }

    json!(annotations)
}

/* -------------------------------------------------------------------- */
/*  Helper Functions                                                    */
/* -------------------------------------------------------------------- */

async fn check_vulnerabilities(component_name: &str) -> Result<Vec<Vulnerability>, SbomError> {
    let client = Client::new();
    let mut vulnerabilities = Vec::new();
    
    // Query OSV database (simplified implementation)
    let query = json!({
        "package": {
            "name": component_name,
            "ecosystem": "detect_ecosystem_from_name"
        }
    });
    
    if let Ok(response) = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .await
    {
        if let Ok(data) = response.json::<serde_json::Value>().await {
            if let Some(vulns) = data.get("vulns").and_then(|v| v.as_array()) {
                for vuln in vulns.iter().take(5) { // Limit to 5 vulns per component
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
                            affected_versions: vec![], // Would be populated from vuln data
                            fixed_versions: vec![],    // Would be populated from vuln data
                            references: vec![],        // Would be populated from vuln data
                        });
                    }
                }
            }
        }
    }
    
    Ok(vulnerabilities)
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

// Using Property/Properties from cyclonedx-bom
