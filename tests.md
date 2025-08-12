# Test Documentation for Betanet Lint

This document outlines the test cases implemented for the `betanet-lint` tool, covering various scenarios for compliance checks and SBOM generation. All tests are located in `src/checks.rs` (for compliance checks) and `tests/cli.rs` (for CLI functionality).

## Overall Compliance Test Scenarios

These tests verify the tool's behavior under different overall compliance outcomes.

### `test_all_checks_pass`
**Purpose**: Verifies that all 11 compliance checks pass when the `BinaryMeta` is configured to be fully compliant. This test also includes detailed assertions for the `details` string of each check to ensure they pass for the correct reasons.
**Status**: PASSED

### `test_9_of_11_checks_pass`
**Purpose**: Verifies that 9 out of 11 compliance checks pass, specifically failing `CHK-05` (Debug Section Stripping) and `CHK-06` (Forbidden Syscalls/APIs).
**Status**: PASSED

### `test_10_of_11_checks_pass`
**Purpose**: Verifies that 10 out of 11 compliance checks pass, specifically failing `CHK-11` (Specification Version Tags).
**Status**: PASSED

## Individual Compliance Check Scenarios (`CHK-01` to `CHK-11`)

These tests verify the behavior of each individual compliance check under both passing and failing conditions.

### `CHK-01: Position-Independent Executable (PIE)`
*   `test_chk01_elf_pie_pass`: ELFBbinary is PIE. **Status**: PASSED
*   `test_chk01_elf_pie_fail`: ELF binary is not PIE. **Status**: PASSED
*   `test_chk01_macho_pie_pass`: Mach-O binary appears to support PIE (heuristic). **Status**: PASSED
*   `test_chk01_macho_pie_fail`: Mach-O PIE detection not fully implemented (no PIE string). **Status**: PASSED
*   `test_chk01_pe_pie_pass`: PE binary appears to support ASLR/PIE (heuristic). **Status**: PASSED
*   `test_chk01_pe_pie_fail`: PE ASLR/PIE detection not fully implemented (no ASLR string). **Status**: PASSED

### `CHK-02: Static Linking Detection`
*   `test_chk02_dynamic_pass`: Binary appears dynamically linked (3+ dynamic libs). **Status**: PASSED
*   `test_chk02_static_fail_indicators`: Binary likely statically linked (static indicators present). **Status**: PASSED
*   `test_chk02_static_fail_few_deps`: Binary likely statically linked (few dynamic libs). **Status**: PASSED

### `CHK-03: Modern Cryptography and libp2p`
*   `test_chk03_modern_crypto_pass`: Sufficient modern crypto detected (2+ keywords). **Status**: PASSED
*   `test_chk03_modern_crypto_fail`: Insufficient modern crypto markers (less than 2 keywords). **Status**: PASSED

### `CHK-04: Reproducible Build Identifiers`
*   `test_chk04_elf_pass`: Build-id like string found in ELF. **Status**: PASSED
*   `test_chk04_elf_fail`: No reproducible build identifier found in ELF. **Status**: PASSED
*   `test_chk04_macho_pass`: UUID-like string found in Mach-O (heuristic). **Status**: PASSED
*   `test_chk04_macho_fail`: No UUID-like string found in Mach-O (heuristic). **Status**: PASSED
*   `test_chk04_pe_pass`: PDB-like string found in PE (heuristic). **Status**: SKIPPED (due to `goblin` library limitations)
*   `test_chk04_pe_fail`: No PDB-like string found in PE (heuristic). **Status**: SKIPPED (due to `goblin` library limitations)

### `CHK-05: Debug Section Stripping`
*   `test_chk05_stripped_pass`: Binary appears to be debug-stripped. **Status**: PASSED
*   `test_chk05_not_stripped_fail`: Debug sections detected. **Status**: PASSED

### `CHK-06: Forbidden Syscalls/APIs`
*   `test_chk06_forbidden_syscalls_pass`: No forbidden syscalls detected. **Status**: PASSED
*   `test_chk06_forbidden_syscalls_fail`: Forbidden syscalls found. **Status**: PASSED

### `CHK-07: Cryptographic Primitive Whitelist`
*   `test_chk07_crypto_whitelist_pass`: No forbidden cryptographic primitives detected. **Status**: PASSED
*   `test_chk07_crypto_whitelist_fail`: Forbidden crypto primitives found. **Status**: PASSED

### `CHK-08: QUIC/HTTP3 Support`
*   `test_chk08_quic_http3_pass`: QUIC/HTTP3 support detected. **Status**: PASSED
*   `test_chk08_quic_http3_fail`: No QUIC/HTTP3 support indicators found. **Status**: PASSED

### `CHK-09: Secure Randomness`
*   `test_chk09_secure_randomness_pass`: Secure RNG sources found. **Status**: PASSED
*   `test_chk09_secure_randomness_fail`: No secure randomness sources detected. **Status**: PASSED

### `CHK-10: SBOM Generation Capability`
*   `test_chk10_sbom_capability_pass`: SBOM generation capability provided by betanet-lint. **Status**: PASSED

### `CHK-11: Specification Version Tags`
*   `test_chk11_spec_version_pass`: Specification version tags found. **Status**: PASSED
*   `test_chk11_spec_version_fail`: No BETANET_SPEC_v*.* version tags found. **Status**: PASSED

## CLI Functionality Test

### `runs_and_writes_report` (in `tests/cli.rs`)
**Purpose**: Verifies that the `betanet-lint` CLI tool runs successfully and produces a compliance report. This test also confirms that the tool's stdout contains expected analysis and report writing messages.
**Status**: PASSED