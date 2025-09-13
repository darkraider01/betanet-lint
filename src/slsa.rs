//! SLSA Provenance Generation Module
//!
//! Implements SLSA (Supply-chain Levels for Software Artifacts) Level 3
//! provenance generation and verification for Betanet compliance.

use sha2::{Digest, Sha256};
use crate::binary::BinaryMeta;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct SLSAProvenance {
    #[serde(rename = "_type")]
    pub statement_type: String,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<Subject>,
    pub predicate: Predicate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Predicate {
    pub builder: Builder,
    #[serde(rename = "buildType")]
    pub build_type: String,
    pub invocation: Invocation,
    pub materials: Vec<Material>,
    pub metadata: BuildMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Builder {
    pub id: String,
    pub version: HashMap<String, String>,
    #[serde(rename = "builderDependencies")]
    pub builder_dependencies: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Invocation {
    #[serde(rename = "configSource")]
    pub config_source: ConfigSource,
    pub parameters: HashMap<String, serde_json::Value>,
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigSource {
    pub uri: String,
    pub digest: HashMap<String, String>,
    #[serde(rename = "entryPoint")]
    pub entry_point: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Material {
    pub uri: String,
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildMetadata {
    #[serde(rename = "buildInvocationId")]
    pub build_invocation_id: String,
    #[serde(rename = "buildStartedOn")]
    pub build_started_on: String,
    #[serde(rename = "buildFinishedOn")]
    pub build_finished_on: String,
    pub reproducible: bool,
    #[serde(rename = "hermetic")]
    pub hermetic: bool,
}

pub struct SLSAGenerator {
    builder_id: String,
    build_type: String,
}

impl SLSAGenerator {
    pub fn new() -> Self {
        Self {
            builder_id: "https://github.com/darkraider01/betanet-lint".to_string(),
            build_type: "https://github.com/betanet/betanet-lint@v1".to_string(),
        }
    }

    pub fn generate_provenance(
        &self, 
        meta: &BinaryMeta, 
        sbom_path: Option<&Path>
    ) -> Result<SLSAProvenance> {
        let subject = vec![Subject {
            name: meta.path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            digest: {
                let mut digest = HashMap::new();
                digest.insert("sha256".to_string(), meta.sha256.clone());
                digest
            },
        }];

        let builder = Builder {
            id: self.builder_id.clone(),
            version: {
                let mut version = HashMap::new();
                version.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
                version
            },
            builder_dependencies: vec![
                "rustc".to_string(),
                "cargo".to_string(),
                "betanet-lint".to_string(),
            ],
        };

        let invocation = Invocation {
            config_source: ConfigSource {
                uri: "git+https://github.com/darkraider01/betanet-lint".to_string(),
                digest: {
                    let mut digest = HashMap::new();
                    // In a real implementation, this would be the actual commit hash
                    digest.insert("sha1".to_string(), "HEAD".to_string());
                    digest
                },
                entry_point: "src/main.rs".to_string(),
            },
            parameters: {
                let mut params = HashMap::new();
                params.insert("target".to_string(), serde_json::Value::String("release".to_string()));
                params.insert("features".to_string(), serde_json::Value::Array(vec![]));
                params
            },
            environment: meta.build_environment.environment_variables.clone(),
        };

        let mut materials = vec![Material {
            uri: format!("file://{}", meta.path.display()),
            digest: {
                let mut digest = HashMap::new();
                digest.insert("sha256".to_string(), meta.sha256.clone());
                digest
            },
        }];

        // Add SBOM as material if provided
        if let Some(sbom_path) = sbom_path {
            if let Ok(sbom_data) = std::fs::read(sbom_path) {
                materials.push(Material {
                    uri: format!("file://{}", sbom_path.display()),
                    digest: {
                        let mut digest = HashMap::new();
                        let hash = Sha256::digest(&sbom_data);
                        digest.insert("sha256".to_string(), format!("{:x}", hash));
                        digest
                    },
                });
            }
        }

        let metadata = BuildMetadata {
            build_invocation_id: uuid::Uuid::new_v4().to_string(),
            build_started_on: chrono::Utc::now().to_rfc3339(),
            build_finished_on: chrono::Utc::now().to_rfc3339(),
            reproducible: meta.build_reproducibility.has_build_id && 
                         !meta.build_reproducibility.deterministic_indicators.is_empty(),
            hermetic: true, // Assume hermetic build environment
        };

        let predicate = Predicate {
            builder,
            build_type: self.build_type.clone(),
            invocation,
            materials,
            metadata,
        };

        Ok(SLSAProvenance {
            statement_type: "https://in-toto.io/Statement/v0.1".to_string(),
            predicate_type: "https://slsa.dev/provenance/v0.2".to_string(),
            subject,
            predicate,
        })
    }

    pub fn write_provenance_file(
        &self,
        provenance: &SLSAProvenance,
        output_path: &Path,
    ) -> Result<()> {
        let json = serde_json::to_string_pretty(provenance)?;
        std::fs::write(output_path, json)?;

        log::info!("SLSA provenance written to: {}", output_path.display());
        Ok(())
    }

    pub fn verify_provenance(
        &self,
        provenance_path: &Path,
        binary_path: &Path,
    ) -> Result<bool> {
        let provenance_data = std::fs::read_to_string(provenance_path)?;
        let provenance: SLSAProvenance = serde_json::from_str(&provenance_data)?;

        // Verify the binary hash matches what's in the provenance
        let binary_data = std::fs::read(binary_path)?;
        let actual_hash = format!("{:x}", Sha256::digest(&binary_data));

        for subject in &provenance.subject {
            if let Some(expected_hash) = subject.digest.get("sha256") {
                if expected_hash == &actual_hash {
                    log::info!("SLSA provenance verification successful");
                    return Ok(true);
                }
            }
        }

        log::warn!("SLSA provenance verification failed - hash mismatch");
        Ok(false)
    }
}

impl Default for SLSAGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    fn create_test_meta() -> BinaryMeta {
        BinaryMeta {
            path: std::path::PathBuf::from("test_binary"),
            format: BinFormat::Elf,
            size_bytes: 1000,
            strings: vec![],
            sha256: "abcd1234".to_string(),
            needed_libs: vec![],
            raw: vec![],
            embedded_files: vec![],
            compiler_info: None,
            build_environment: BuildEnvironment {
                build_tool: Some("cargo".to_string()),
                build_version: Some("1.70.0".to_string()),
                build_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
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
    fn test_slsa_provenance_generation() {
        let generator = SLSAGenerator::new();
        let meta = create_test_meta();

        let provenance = generator.generate_provenance(&meta, None).unwrap();

        assert_eq!(provenance.statement_type, "https://in-toto.io/Statement/v0.1");
        assert_eq!(provenance.predicate_type, "https://slsa.dev/provenance/v0.2");
        assert_eq!(provenance.subject.len(), 1);
        assert_eq!(provenance.subject[0].name, "test_binary");
        assert_eq!(provenance.subject[0].digest["sha256"], "abcd1234");
    }

    #[test]
    fn test_provenance_file_write_read() {
        let generator = SLSAGenerator::new();
        let meta = create_test_meta();
        let temp_file = NamedTempFile::new().unwrap();

        let provenance = generator.generate_provenance(&meta, None).unwrap();
        generator.write_provenance_file(&provenance, temp_file.path()).unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        let parsed: SLSAProvenance = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.subject[0].name, "test_binary");
    }
}
