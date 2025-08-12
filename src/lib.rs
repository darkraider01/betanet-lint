pub mod binary;
pub mod checks;
pub mod sbom;

pub use binary::BinaryMeta;
pub use checks::{CheckResult, run_all_checks, write_report_json};
pub use sbom::{SbomFormat, SbomOptions, LicenseScanDepth, write_sbom_with_options};
