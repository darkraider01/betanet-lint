use crate::binary::BinaryMeta;

#[derive(Debug)]
pub struct CheckResult {
    pub id: &'static str,
    pub pass: bool,
    pub details: String,
}

pub fn check_libp2p(meta: &BinaryMeta) -> CheckResult {
    tracing::info!("Running CHK-03: Detecting libp2p usage.");
    tracing::debug!("BinaryMeta for CHK-03: {:?}", meta);

    let mut evidence = Vec::new();

    for lib in &meta.linked_libs {
        if lib.to_lowercase().contains("libp2p") {
            evidence.push(format!("linked: {}", lib));
            tracing::debug!("Found libp2p in linked library: {}", lib);
        }
    }

    for s in &meta.strings {
        if s.to_lowercase().contains("libp2p") {
            evidence.push(format!("string: {}", s));
            tracing::debug!("Found libp2p in extracted string: {}", s);
        }
    }

    let pass = !evidence.is_empty();
    let details = if evidence.is_empty() {
        "No libp2p found".into()
    } else {
        evidence.join("; ")
    };

    if pass {
        tracing::info!("CHK-03 PASS: {}", details);
    } else {
        tracing::info!("CHK-03 FAIL: {}", details);
    }

    CheckResult {
        id: "CHK-03",
        pass,
        details,
    }
}
