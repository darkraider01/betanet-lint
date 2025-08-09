# Betanet-Lint

A **Betanet spec-compliance linter** written in Rust.  
It checks compiled binaries against the Betanet specification’s **11 must-have features** and produces a **pass/fail report** along with an optional **SBOM (Software Bill of Materials)**.

## Features (current)
- CLI tool built with [Clap](https://docs.rs/clap)
- Binary parsing via [goblin](https://docs.rs/goblin)
- String extraction for quick evidence scanning
- First implemented check: **CHK-03: Detect `libp2p` usage**
- Ready to extend for all 11 checks
- SBOM generation planned via [CycloneDX](https://cyclonedx.org/)

---

## Installation

### Prerequisites
- [Rust](https://rustup.rs/) toolchain (`rustc`, `cargo`) installed
- A C compiler (`gcc` or `clang`) if you want to build test fixtures

### Clone & Build
```bash
git clone https://github.com/your-username/betanet-lint.git
cd betanet-lint
cargo build --release
```
The compiled binary will be at:

```arduino
target/release/betanet-lint
```
## Usage
Basic
```bash
./betanet-lint --binary /path/to/target/binary
```
Example:

```bash
./betanet-lint --binary ./fixture_good
```
Output:

```csharp
Check CHK-03: PASS (string: kyber x25519 ed25519 libp2p quic)
```
## Development
Project Structure
```php
src/
  main.rs      # CLI entrypoint
  binary.rs    # Binary parsing & string extraction
  checks.rs    # Individual compliance checks
Cargo.toml     # Dependencies & metadata
```
Adding a New Check
Create a new function in src/checks.rs:

```rust
pub fn check_xyz(meta: &BinaryMeta) -> CheckResult { /* ... */ }
```
Append it to the check runner in main.rs.

Rebuild and test.

Test Fixtures
To create a simple test binary that passes CHK-03:

```bash
cat > fixture_good.c <<'C'
#include <stdio.h>
static const char *markers = "kyber x25519 ed25519 libp2p quic";
int main(void){
    puts("fixture for betanet-lint");
    (void)markers;
    return 0;
}
C
gcc -O0 fixture_good.c -o fixture_good
```
## Roadmap
- CLI argument parsing
- Binary parsing + string extraction
- CHK-03 (libp2p detection)
- All remaining 10 checks
- SBOM generation (CycloneDX JSON)
- GitHub Action template

## License
MIT License © 2025 Your Name