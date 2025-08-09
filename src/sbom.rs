//! Comprehensive SBOM generation (CycloneDX and SPDX formats)

use std::{fs, path::PathBuf};
use crate::binary::{BinFormat, BinaryMeta};
use serde_json::json;
use thiserror::Error;
use strum::EnumString;

// Use the correct imports for cyclonedx-bom
use cyclonedx_bom::prelude::*;
use cyclonedx_bom::models::{
    bom::Bom,
    component::{Component, ComponentType, ComponentScope},
    metadata::Metadata,
    tool::{Tool, Tools},
    hash::{Hash, HashType},
    external_reference::{ExternalReference, ExternalReferenceType},
};

#[derive(Debug, EnumString, Clone, Copy)]
pub enum SbomFormat {
    #[strum(serialize = "cyclonedx")]
    CycloneDx,
    #[strum(serialize = "spdx")]
    Spdx,
}

#[derive(Error, Debug)]
pub enum SbomError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SBOM generation error: {0}")]
    Generation(String),
}

/// Public façade - keep the same interface as before
pub fn write_sbom_json(out_path: &PathBuf, meta: &BinaryMeta) -> Result<(), String> {
    write_sbom(out_path, meta, SbomFormat::CycloneDx).map_err(|e| e.to_string())
}

/// Enhanced interface with format selection
pub fn write_sbom(
    out_path: &PathBuf,
    meta: &BinaryMeta,
    format: SbomFormat,
) -> Result<(), SbomError> {
    let data = match format {
        SbomFormat::CycloneDx => generate_cyclonedx(meta)?,
        SbomFormat::Spdx => generate_spdx(meta)?,
    };
    fs::write(out_path, data)?;
    Ok(())
}

/* -------------------------------------------------------------------- */
/*  CycloneDX Generation                                                */
/* -------------------------------------------------------------------- */

fn generate_cyclonedx(meta: &BinaryMeta) -> Result<String, SbomError> {
    // Create the main component (the analyzed binary)
    let main_component = Component {
        component_type: ComponentType::Application,
        name: NormalizedString::new(
            meta.path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ).map_err(|e| SbomError::Generation(e.to_string()))?,
        version: Some(NormalizedString::new("unknown")
            .map_err(|e| SbomError::Generation(e.to_string()))?),
        scope: Some(ComponentScope::Required),
        hashes: Some(vec![Hash {
            algorithm: HashType::Sha256,
            content: NormalizedString::new(&meta.sha256)
                .map_err(|e| SbomError::Generation(e.to_string()))?,
        }]),
        external_references: Some(vec![ExternalReference {
            reference_type: ExternalReferenceType::Other,
            url: Uri::new(format!("file://{}", meta.path.display()))
                .map_err(|e| SbomError::Generation(e.to_string()))?,
            comment: Some(NormalizedString::new("Analyzed binary file")
                .map_err(|e| SbomError::Generation(e.to_string()))?),
            ..ExternalReference::default()
        }]),
        ..Component::default()
    };

    // Create dependency components
    let mut components = vec![main_component];
    
    for lib_name in &meta.needed_libs {
        let lib_component = Component {
            component_type: ComponentType::Library,
            name: NormalizedString::new(lib_name)
                .map_err(|e| SbomError::Generation(e.to_string()))?,
            scope: Some(ComponentScope::Required),
            ..Component::default()
        };
        components.push(lib_component);
    }

    // Add components detected from strings (crypto/networking libraries)
    let crypto_keywords = ["libp2p", "kyber", "x25519", "ed25519", "quic"];
    for keyword in &crypto_keywords {
        if meta.strings.iter().any(|s| s.to_lowercase().contains(keyword)) {
            let crypto_component = Component {
                component_type: ComponentType::Library,
                name: NormalizedString::new(&format!("crypto-{}", keyword))
                    .map_err(|e| SbomError::Generation(e.to_string()))?,
                version: Some(NormalizedString::new("detected")
                    .map_err(|e| SbomError::Generation(e.to_string()))?),
                scope: Some(ComponentScope::Optional),
                ..Component::default()
            };
            components.push(crypto_component);
        }
    }

    // Create the BOM
    let mut bom = Bom::default();
    bom.serial_number = Some(
        UrnUuid::generate().map_err(|e| SbomError::Generation(e.to_string()))?
    );
    bom.metadata = Some(Metadata {
        tools: Some(Tools::List(vec![Tool {
            name: Some(NormalizedString::new("betanet-lint")
                .map_err(|e| SbomError::Generation(e.to_string()))?),
            version: Some(NormalizedString::new(env!("CARGO_PKG_VERSION"))
                .map_err(|e| SbomError::Generation(e.to_string()))?),
            vendor: Some(NormalizedString::new("Betanet")
                .map_err(|e| SbomError::Generation(e.to_string()))?),
            ..Tool::default()
        }])),
        ..Metadata::default()
    });
    bom.components = Some(components);

    // Serialize to JSON
    let mut output = Vec::new();
    bom.output_as_json_v1_5(&mut output)
        .map_err(|e| SbomError::Generation(format!("CycloneDX serialization failed: {}", e)))?;
    
    String::from_utf8(output)
        .map_err(|e| SbomError::Generation(format!("UTF-8 conversion failed: {}", e)))
}

/* -------------------------------------------------------------------- */
/*  SPDX Generation (Simplified)                                       */
/* -------------------------------------------------------------------- */

fn generate_spdx(meta: &BinaryMeta) -> Result<String, SbomError> {
    // Since the spdx-rs crate structure is complex, we'll generate a simple
    // SPDX-compatible JSON structure manually
    let spdx_doc = json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": chrono::Utc::now().to_rfc3339(),
            "creators": ["Tool: betanet-lint"],
            "licenseListVersion": "3.20"
        },
        "name": format!("betanet-lint-sbom-{}", meta.path.file_name().unwrap_or_default().to_string_lossy()),
        "dataLicense": "CC0-1.0",
        "documentNamespace": format!("https://betanet.org/spdx/{}", uuid::Uuid::new_v4()),
        "packages": generate_spdx_packages(meta),
        "relationships": generate_spdx_relationships(meta),
        "files": [{
            "SPDXID": "SPDXRef-File-Binary",
            "fileName": meta.path.to_string_lossy(),
            "checksums": [{
                "algorithm": "SHA256",
                "checksumValue": meta.sha256
            }],
            "copyrightText": "NOASSERTION"
        }]
    });

    serde_json::to_string_pretty(&spdx_doc).map_err(SbomError::Json)
}

fn generate_spdx_packages(meta: &BinaryMeta) -> serde_json::Value {
    let mut packages = vec![json!({
        "SPDXID": "SPDXRef-Package-Binary",
        "name": meta.path.file_name().unwrap_or_default().to_string_lossy(),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": true,
        "checksums": [{
            "algorithm": "SHA256",
            "checksumValue": meta.sha256
        }],
        "copyrightText": "NOASSERTION"
    })];

    // Add library packages
    for (idx, lib) in meta.needed_libs.iter().enumerate() {
        packages.push(json!({
            "SPDXID": format!("SPDXRef-Package-Lib-{}", idx),
            "name": lib,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "copyrightText": "NOASSERTION"
        }));
    }

    json!(packages)
}

fn generate_spdx_relationships(meta: &BinaryMeta) -> serde_json::Value {
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package-Binary"
    })];

    // Add dependency relationships
    for idx in 0..meta.needed_libs.len() {
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Package-Binary",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": format!("SPDXRef-Package-Lib-{}", idx)
        }));
    }

    json!(relationships)
}
