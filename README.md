# Betanet-Lint: Compliance Verification Tool

[![CI](https://github.com/darkraider01/betanet-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/darkraider01/betanet-lint/actions/workflows/ci.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/)
[![Security Scorecard](https://api.securityscorecards.dev/projects/github.com/darkraider01/betanet-lint/badge)](https://securityscorecards.dev/viewer/?uri=github.com/darkraider01/betanet-lint)

A robust, secure compliance verification tool for Betanet 1.1 specification (Section 11). This tool verifies that compiled binaries meet the 13 normative requirements specified in Betanet 1.1 §11 through sophisticated protocol analysis rather than simple string scanning.

## 🔒 Security Features

- **No Self-Passes**: Tool analyzes all binaries objectively without special treatment for itself
- **Secure Networking**: All network operations use proper timeouts, rate limiting, and security controls
- **SLSA Level 3**: Generates cryptographically signed provenance attestations
- **Hardened CI/CD**: All GitHub Actions pinned to commit SHAs with minimal permissions
- **Memory Safety**: Efficient analysis with memory mapping for large binaries

## 📋 Betanet 1.1 §11 Compliance Checks

This tool implements verification for all 13 normative requirements:

| Check | Requirement | Description |
|-------|-------------|-------------|
| BN-11.1 | HTX Transport | HTX over TCP-443 and QUIC-443 with origin-mirrored TLS + ECH |
| BN-11.2 | Access Tickets | Negotiated-carrier, replay-bound access tickets with rate-limits |
| BN-11.3 | Noise XK | Inner Noise XK with key separation, nonce lifecycle, rekeying |
| BN-11.4 | HTTP Emulation | HTTP/2/3 emulation with adaptive cadences |
| BN-11.5 | SCION Bridging | HTX-tunnelled transition for non-SCION links |
| BN-11.6 | Protocol Support | Betanet transport protocols (/betanet/htx/1.1.0, /betanet/htxquic/1.1.0) |
| BN-11.7 | Bootstrap | Bootstrap via rotating rendezvous with PoW rate-limits |
| BN-11.8 | Mixnode Selection | BeaconSet mixnode selection with path diversity |
| BN-11.9 | Alias Ledger | Finality-bound 2-of-3 alias ledger verification |
| BN-11.10 | Cashu Vouchers | 128-B Cashu vouchers with PoW adverts |
| BN-11.11 | Governance | Governance with anti-concentration caps and diversity checks |
| BN-11.12 | Anti-correlation | Anti-correlation fallback with cover connections |
| BN-11.13 | SLSA Provenance | SLSA 3 provenance artifacts for reproducible builds |

## 🚀 Installation

### Prerequisites
- Rust 1.70+ with `cargo`
- C compiler (for test fixtures)
- Git (for source builds)

### From Source (Recommended)
```bash
git clone https://github.com/darkraider01/betanet-lint.git
cd betanet-lint
cargo build --release

# Binary will be at target/release/betanet-lint
```

### Verify Installation
```bash
./target/release/betanet-lint --help
```

## 📖 Usage

### Basic Compliance Check
```bash
betanet-lint --binary ./your-binary --report compliance-report.json
```

### Enhanced SBOM Generation
```bash
# Generate comprehensive SBOM with all security features
betanet-lint \
  --binary ./your-binary \
  --report compliance-report.json \
  --sbom enhanced-sbom.json \
  --sbom-format cyclonedx \
  --generate-cbom \
  --include-vulns \
  --slsa-level 3
```

### Offline Mode (Air-Gapped Environments)
```bash
betanet-lint \
  --binary ./your-binary \
  --report compliance-report.json \
  --sbom offline-sbom.json \
  --offline
```

### CI/CD Integration
```bash
# Exit code 0: All checks passed
# Exit code 2: One or more checks failed  
# Exit code 1: Runtime error

betanet-lint --binary ./release-binary --report report.json --offline
if [ $? -eq 0 ]; then
    echo "✅ Betanet 1.1 compliant"
else
    echo "❌ Compliance issues detected"
    exit 1
fi
```

## 🔍 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--binary <PATH>` | Path to binary to analyze | Required |
| `--report <PATH>` | Compliance report output path | Required |
| `--sbom <PATH>` | SBOM output path (optional) | None |
| `--sbom-format <FORMAT>` | SBOM format: cyclonedx or spdx | cyclonedx |
| `--include-vulns` | Include vulnerability data | false |
| `--generate-cbom` | Generate Cryptographic BOM | false |
| `--generate-vex` | Generate VEX statements | false |
| `--slsa-level <LEVEL>` | SLSA provenance level (1-4) | 3 |
| `--offline` | Disable network vulnerability checks | false |

## 🧪 Analysis Methodology

### Protocol Verification (Not String Scanning)

Unlike simple string-based tools, betanet-lint uses sophisticated binary analysis:

- **Symbol Analysis**: Examines imported/exported function symbols
- **Section Parsing**: Analyzes binary sections using proper format parsers (ELF/PE/Mach-O)
- **Library Dependencies**: Inspects linked libraries and their capabilities
- **Cryptographic Component Detection**: Identifies actual crypto implementations
- **Build Reproducibility**: Verifies deterministic build practices

### Memory Efficiency

- Memory-mapped file access for large binaries (>10MB)
- Streaming SHA256 computation for files >100MB
- Intelligent string extraction with noise filtering
- Limited processing to prevent resource exhaustion

## 📊 Report Format

### Compliance Report
```json
{
  "metadata": {
    "tool": "betanet-lint",
    "version": "0.2.0", 
    "timestamp": "2024-01-01T00:00:00Z",
    "spec_version": "Betanet 1.1"
  },
  "summary": {
    "total_checks": 13,
    "passed_checks": 10,
    "failed_checks": 3,
    "compliance_rate": 76.9,
    "overall_compliance": false
  },
  "compliance_matrix": {
    "transport_layer": {"passed": 3, "total": 4, "status": "NON_COMPLIANT"},
    "cryptography": {"passed": 2, "total": 3, "status": "NON_COMPLIANT"},
    "build_integrity": {"passed": 1, "total": 1, "status": "COMPLIANT"}
  },
  "detailed_results": [...],
  "recommendations": [...],
  "next_steps": [...]
}
```

### SBOM with Provenance
- **CycloneDX 1.5**: Industry standard with security metadata
- **SPDX 2.3**: Alternative format with license focus
- **SLSA Provenance**: Cryptographic build attestations
- **VEX Statements**: Vulnerability exploitability exchange
- **CBOM**: Cryptographic bill of materials

## 🔐 Security Considerations

### Network Security
- All HTTP requests use 30-second timeouts
- Proper User-Agent identification
- SSL certificate verification enforced
- Rate limiting to prevent abuse
- No sensitive data in requests

### Build Security
- Reproducible builds with `SOURCE_DATE_EPOCH`
- SLSA Level 3 provenance generation
- Cryptographic attestations for all artifacts
- Build environment isolation

### Supply Chain Security
- All dependencies audited with `cargo-audit`
- License compliance with `cargo-deny`
- Vulnerability scanning integration
- Signed releases with provenance

## 🏗️ Development

### Building from Source
```bash
git clone https://github.com/darkraider01/betanet-lint.git
cd betanet-lint

# Install security audit tools
cargo install cargo-audit cargo-deny

# Security checks
cargo audit
cargo deny check

# Build with security flags
export RUSTFLAGS="-D warnings -C target-feature=+crt-static"
cargo build --release --locked

# Run tests
cargo test --all --locked --verbose

# Integration test
./target/release/betanet-lint --binary ./target/release/betanet-lint --report self-test.json --offline
```

### Testing
```bash
# Unit tests
cargo test

# Integration tests  
cargo test --test integration

# Compliance verification
./.github/scripts/test-compliance.sh
```

## 📚 Documentation

- [Betanet 1.1 Specification](https://betanet.org/spec/1.1/)
- [SLSA Framework](https://slsa.dev/)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [SPDX License Standard](https://spdx.dev/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run security checks (`cargo audit && cargo deny check`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Code Quality Standards
- All code must pass `cargo clippy --all-targets -- -D warnings`
- Security audit with `cargo audit` must pass
- License compliance with `cargo deny check` must pass
- All tests must pass: `cargo test --all`
- Documentation required for public APIs

## 📄 License

This project is licensed under the MIT OR Apache-2.0 License - see the [LICENSE](LICENSE) files for details.

## 🙏 Acknowledgments

- [Betanet Project](https://betanet.org/) for the specification
- [SLSA Framework](https://slsa.dev/) for supply chain security
- [CycloneDX](https://cyclonedx.org/) for SBOM standards
- [Rust Security Advisory Database](https://github.com/RustSec/advisory-db)

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/darkraider01/betanet-lint/issues)
- Security Issues: Please report security vulnerabilities privately
- Documentation: [Wiki](https://github.com/darkraider01/betanet-lint/wiki)

---

**Note**: This tool performs actual protocol compliance verification according to Betanet 1.1 specification. It does not accept artificial data injection or provide self-passes. All analysis results reflect genuine binary characteristics and protocol implementation status.
