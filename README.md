## Betanet Lint

A fast Betanet spec-compliance linter written in Rust.

- Checks a compiled binary against the Betanet spec’s 11 checks (heuristics)
- Prints a readable table, writes a JSON report, and can optionally emit a CycloneDX SBOM
- Exits non‑zero when any check fails (handy for CI)

### Installation
- Prerequisites: Rust toolchain (rustup), a C compiler only if you want to build local fixtures
- Build:
  ```bash
  cargo build --release
  ```
  The binary is at `target/release/betanet-lint`.

### Usage
```bash
./target/release/betanet-lint \
  --binary /path/to/your/binary \
  --report ./report.json \
  [--sbom ./sbom.json]
```
- `--binary` (required): path to the candidate binary to analyze
- `--report` (required): path to write the JSON compliance report
- `--sbom` (optional): path to write a CycloneDX v1.5 JSON SBOM

Example:
```bash
./target/release/betanet-lint \
  --binary ./fixture_good \
  --report ./report.json \
  --sbom ./sbom.json
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
- Run tests: `cargo test`
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
