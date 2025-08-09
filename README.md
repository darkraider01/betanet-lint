## Betanet Lint

`betanet-lint` is a robust, Rust-based command-line interface (CLI) tool designed to enforce compliance with the Betanet specification for compiled binaries. It systematically analyzes binaries to ensure they adhere to a set of predefined security, performance, and best-practice heuristics.

**Key Features:**

- **Comprehensive Compliance Checks**: Implements 11 distinct checks (heuristics) against a given binary to assess its adherence to the Betanet specification. These checks cover areas such as binary format, linking, cryptography, build reproducibility, and more.
- **Detailed Reporting**: Generates a human-readable table output to the console and a structured JSON report, providing a clear overview of check results (pass/fail) and associated details.
- **Software Bill of Materials (SBOM) Generation**: Optionally produces a Software Bill of Materials in industry-standard formats like CycloneDX or SPDX, detailing the components and dependencies identified within the analyzed binary.
- **CI/CD Integration**: Designed for seamless integration into Continuous Integration/Continuous Deployment pipelines, exiting with non-zero status codes on check failures to facilitate automated gating.

This tool is essential for developers and auditors working within the Betanet ecosystem, ensuring that deployed binaries meet stringent compliance requirements before deployment.

### Installation
- Prerequisites: Rust toolchain (rustup), a C compiler only if you want to build local fixtures
- Build:
  ```bash
  cargo build --release
  ```
  The binary is at `target/release/betanet-lint`.

### Usage
The `betanet-lint` tool now has subcommands for linting and testing.

To run compliance checks on a binary:
```bash
# Basic SBOM generation (backward compatible)
cargo run -- --binary ./app --report report.json --sbom sbom.json

# Comprehensive SBOM with all enhancements
cargo run -- --binary ./app --report report.json --sbom comprehensive-sbom.json \
  --sbom-format cyclonedx --include-vulns --generate-cbom \
  --license-scan comprehensive --generate-vex --slsa-level 3

# Generate both formats with different feature sets
cargo run -- --binary ./app --report report.json --sbom app-cyclonedx.json \
  --sbom-format cyclonedx --include-vulns --generate-cbom

cargo run -- --binary ./app --report report.json --sbom app-spdx.json \
  --sbom-format spdx --license-scan deep
```
- `--binary` (required): path to the candidate binary to analyze
- `--report` (required): path to write the JSON compliance report
- `--sbom` (optional): path to write a CycloneDX v1.5 JSON SBOM. If omitted, no SBOM is generated.
- `--sbom-format` (optional): specifies the SBOM format, either `cyclonedx` (default) or `spdx`.
- `--include-vulns` (optional): includes vulnerability data in the SBOM (boolean flag).
- `--generate-cbom` (optional): generates a Cryptographic Bill of Materials (CBOM) within the SBOM (boolean flag).
- `--license-scan` (optional): sets the license scanning depth. Options: `basic` (default), `comprehensive`, `deep`.
- `--generate-vex` (optional): generates VEX (Vulnerability Exploitability eXchange) statements (boolean flag).
- `--slsa-level` (optional): specifies the SLSA (Supply-chain Levels for Software Artifacts) provenance level (integer 1-4).

To run the integrated test suite:
```bash
cargo run -- test
```

Exit codes:
- 0: all checks passed
- 2: at least one check failed
- 1: runtime error (e.g., failed to read the binary)

### What it checks (current heuristics)
- CHK‑01: Position‑Independent Executable (PIE) where detectable
- CHK‑02: Avoid obvious static linking artifacts
- CHK‑03: libp2p and modern crypto indicators (e.g., kyber, x25519, ed25519, quic)
- CHK‑04: Reproducible build identifiers (ELF GNU build‑id, Mach‑O UUID, PE PDB GUID)
- CHK‑05: Stripped debug sections indicators
- CHK‑06: No forbidden syscalls/API names
- CHK‑07: No disallowed crypto primitives (e.g., rsa, des, md5)
- CHK‑08: QUIC/HTTP3 indicators
- CHK‑09: Secure randomness indicators
- CHK‑10: SBOM generation capability
- CHK‑11: Spec version tag indicator (e.g., `BETANET_SPEC_v1.0`)

### CI
Two workflows are included:
- `ci.yml`: cross‑platform build, clippy, and tests on push/PR
- `compliance.yml`: builds a tiny example fixture and runs the linter, uploading `report.json` and `sbom.json` as artifacts

You can adapt `compliance.yml` to run the linter on your own binary.

### Development
- Run integrated tests: `cargo run -- test`
- Run unit/integration tests: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Example fixture (not tracked; generate locally if needed):
  ```bash
  cat > fixture_good.c <<'C'
  #include <stdio.h>
  static const char *markers = "kyber x25519 ed25519 libp2p quic BETANET_SPEC_v1.0 /dev/urandom";
  int main(void){ (void)markers; puts("fixture"); return 0; }
  C
  gcc -O0 fixture_good.c -o fixture_good
  ```

### License
MIT © 2025
