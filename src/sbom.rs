use crate::binary::BinaryMeta;
use serde_json::json;
use std::{fs, path::PathBuf};

/// Writes a very small SBOM JSON to `path`.
pub fn write_sbom_json(path: &PathBuf, meta: &BinaryMeta) -> Result<(), String> {
    let sbom = json!({
        "bom_format": "CycloneDX",
        "spec_version": 1,
        "metadata": {
            "binary_path": meta.path.to_string_lossy(),
            "sha256": meta.sha256,
            "size_bytes": meta.size_bytes,
            "format": meta.format.clone().unwrap_or_else(|| "unknown".to_string())
        },
        "components": meta.strings.iter()
            .filter(|s| {
                let low = s.to_lowercase();
                low.contains("libp2p") || low.contains("kyber") || low.contains("x25519") || low.contains("ed25519") || low.contains("quic")
            })
            .take(20)
            .map(|s| json!({ "name": s }))
            .collect::<Vec<_>>()
    });

    fs::write(path, serde_json::to_string_pretty(&sbom).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
