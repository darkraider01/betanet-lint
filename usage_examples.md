# CLI Usage Examples for Betanet Lint Checks

This document provides conceptual command-line interface (CLI) usage examples for `betanet-lint`, demonstrating how to trigger pass and fail scenarios for each of the 11 compliance checks. These examples describe the characteristics of a hypothetical binary (fixture) and the `cargo run` command to analyze it.

**Note**: Creating binaries with precise characteristics for all checks across different operating systems can be complex. These examples illustrate the *principles* for passing or failing each check.

---

## CHK-01: Position-Independent Executable (PIE)

### Scenario: Pass (ELF PIE)
A binary compiled as a Position-Independent Executable (PIE).
```c
// example_pie.c
#include <stdio.h>
int main() {
    printf("This is a PIE example.\n");
    return 0;
}
```
**Compilation (Linux/macOS)**:
`gcc -fPIE -pie example_pie.c -o example_pie_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_pie_pass --report report_chk01_pie_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-01   | PASS   | ELF binary is position-independent (ET_DYN) |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (ELF non-PIE)
A binary compiled as a non-PIE executable.
```c
// example_non_pie.c
#include <stdio.h>
int main() {
    printf("This is a non-PIE example.\n");
    return 0;
}
```
**Compilation (Linux/macOS)**:
`gcc example_non_pie.c -o example_non_pie_fail` (without -fPIE -pie)

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_non_pie_fail --report report_chk01_non_pie_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-01   | FAIL   | ELF binary is not PIE (e_type: 2)        |
+----------+--------+------------------------------------------+
```

---

## CHK-02: Static Linking Detection

### Scenario: Pass (Dynamically Linked)
A binary that primarily uses dynamic libraries (e.g., standard system libraries).
```c
// example_dynamic.c
#include <stdio.h>
#include <string.h>
int main() {
    char greeting[] = "Hello, dynamic world!";
    puts(greeting);
    return 0;
}
```
**Compilation**: Standard compilation (e.g., `gcc example_dynamic.c -o example_dynamic_pass`) usually results in dynamic linking.

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_dynamic_pass --report report_chk02_dynamic_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-02   | PASS   | Appears dynamically linked - X dependencies found |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (Likely Statically Linked - Indicators Present)
A binary that contains common static linking indicators (e.g., from a static library).
```c
// example_static_indicators.c
// This is conceptual; actual static linking requires linking against .a files.
// Assume this binary was linked statically and contains strings like "static_lib".
#include <stdio.h>
const char* static_marker = "static_lib_version_1.0";
int main() {
    printf("This is a static example: %s\n", static_marker);
    return 0;
}
```
**Compilation**: Requires linking with static libraries, e.g., `gcc example_static_indicators.c -static -o example_static_indicators_fail`.

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_static_indicators_fail --report report_chk02_static_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-02   | FAIL   | Likely statically linked - indicators: ["static_lib"], deps: X |
+----------+--------+------------------------------------------+
```

---

## CHK-03: Modern Cryptography and libp2p

### Scenario: Pass (Sufficient Modern Crypto)
A binary containing at least two modern crypto/libp2p keywords.
```c
// example_modern_crypto_pass.c
#include <stdio.h>
const char* crypto_strings[] = {
    "Using libp2p for network communication",
    "Key exchange with X25519 algorithm",
    "Data encrypted with Kyber"
};
int main() {
    printf("%s\n%s\n", crypto_strings[0], crypto_strings[1]);
    return 0;
}
```
**Compilation**: `gcc example_modern_crypto_pass.c -o example_modern_crypto_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_modern_crypto_pass --report report_chk03_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-03   | PASS   | Modern crypto detected: ["libp2p", "x25519"] |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (Insufficient Modern Crypto)
A binary containing less than two modern crypto/libp2p keywords.
```c
// example_modern_crypto_fail.c
#include <stdio.h>
const char* crypto_string = "Only using old DES encryption"; // Not a modern keyword
int main() {
    printf("%s\n", crypto_string);
    return 0;
}
```
**Compilation**: `gcc example_modern_crypto_fail.c -o example_modern_crypto_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_modern_crypto_fail --report report_chk03_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-03   | FAIL   | Insufficient modern crypto markers: [] (need 2+) |
+----------+--------+------------------------------------------+
```

---

## CHK-04: Reproducible Build Identifiers

### Scenario: Pass (Build ID Present)
A binary containing a build-id like hex string (for ELF) or UUID indicators (for Mach-O). *Note: PE PDB GUIDs are currently not supported due to external library limitations.*
```c
// example_reproducible_pass.c
#include <stdio.h>
const char* build_id = "0123456789abcdef0123456789abcdef"; // Example build ID
int main() {
    printf("Build ID: %s\n", build_id);
    return 0;
}
```
**Compilation**: `gcc example_reproducible_pass.c -o example_reproducible_pass` (On Linux, actual build-id can be generated with `-Wl,--build-id`).

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_reproducible_pass --report report_chk04_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-04   | PASS   | Build-id like string found: 0123456789abcdef0123456789abcdef |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (No Build ID)
A binary without reproducible build identifiers.
```c
// example_reproducible_fail.c
#include <stdio.h>
int main() {
    printf("No special identifiers.\n");
    return 0;
}
```
**Compilation**: `gcc example_reproducible_fail.c -o example_reproducible_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_reproducible_fail --report report_chk04_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-04   | FAIL   | No reproducible build identifier found (heuristic) |
+----------+--------+------------------------------------------+
```

---

## CHK-05: Debug Section Stripping

### Scenario: Pass (Debug-Stripped)
A binary with debug information removed.
```c
// example_stripped_pass.c
#include <stdio.h>
int main() {
    printf("This binary is stripped.\n");
    return 0;
}
```
**Compilation**: `gcc -s example_stripped_pass.c -o example_stripped_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_stripped_pass --report report_chk05_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-05   | PASS   | Binary appears to be debug-stripped      |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (Not Debug-Stripped)
A binary containing debug information.
```c
// example_stripped_fail.c
#include <stdio.h>
int main() {
    printf("This binary is not stripped.\n");
    return 0;
}
```
**Compilation**: `gcc -g example_stripped_fail.c -o example_stripped_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_stripped_fail --report report_chk05_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-05   | FAIL   | Debug sections detected: [".debug_info"] |
+----------+--------+------------------------------------------+
```

---

## CHK-06: Forbidden Syscalls/APIs

### Scenario: Pass (No Forbidden Calls)
A binary that does not use any forbidden syscalls or API names.
```c
// example_safe_syscalls_pass.c
#include <stdio.h>
int main() {
    printf("Safe operations.\n");
    return 0;
}
```
**Compilation**: `gcc example_safe_syscalls_pass.c -o example_safe_syscalls_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_safe_syscalls_pass --report report_chk06_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-06   | PASS   | No forbidden syscalls detected           |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (Forbidden Calls Present)
A binary that uses a forbidden syscall or API name.
```c
// example_forbidden_syscalls_fail.c
#include <stdio.h>
#include <stdlib.h> // For system()
int main() {
    system("echo Hello"); // Forbidden syscall
    return 0;
}
```
**Compilation**: `gcc example_forbidden_syscalls_fail.c -o example_forbidden_syscalls_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_forbidden_syscalls_fail --report report_chk06_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-06   | FAIL   | Forbidden syscalls found: ["system"]     |
+----------+--------+------------------------------------------+
```

---

## CHK-07: Cryptographic Primitive Whitelist

### Scenario: Pass (No Forbidden Crypto)
A binary that does not contain references to forbidden cryptographic primitives.
```c
// example_safe_crypto_pass.c
#include <stdio.h>
const char* allowed_crypto = "AES256_GCM"; // Example of allowed crypto
int main() {
    printf("%s\n", allowed_crypto);
    return 0;
}
```
**Compilation**: `gcc example_safe_crypto_pass.c -o example_safe_crypto_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_safe_crypto_pass --report report_chk07_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-07   | PASS   | No forbidden cryptographic primitives detected |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (Forbidden Crypto Present)
A binary that contains references to forbidden cryptographic primitives.
```c
// example_forbidden_crypto_fail.c
#include <stdio.h>
const char* forbidden_crypto = "Using MD5 for hashing"; // Example of forbidden crypto
int main() {
    printf("%s\n", forbidden_crypto);
    return 0;
}
```
**Compilation**: `gcc example_forbidden_crypto_fail.c -o example_forbidden_crypto_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_forbidden_crypto_fail --report report_chk07_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-07   | FAIL   | Forbidden crypto primitives found: ["md5"] |
+----------+--------+------------------------------------------+
```

---

## CHK-08: QUIC/HTTP3 Support

### Scenario: Pass (QUIC/HTTP3 Indicators Present)
A binary containing indicators of QUIC or HTTP3 support.
```c
// example_quic_http3_pass.c
#include <stdio.h>
const char* protocol_string = "QUIC protocol enabled";
int main() {
    printf("%s\n", protocol_string);
    return 0;
}
```
**Compilation**: `gcc example_quic_http3_pass.c -o example_quic_http3_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_quic_http3_pass --report report_chk08_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-08   | PASS   | QUIC/HTTP3 support detected: ["quic"]    |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (No QUIC/HTTP3 Indicators)
A binary without indicators of QUIC or HTTP3 support.
```c
// example_quic_http3_fail.c
#include <stdio.h>
const char* protocol_string = "Only HTTP/1.1 support";
int main() {
    printf("%s\n", protocol_string);
    return 0;
}
```
**Compilation**: `gcc example_quic_http3_fail.c -o example_quic_http3_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_quic_http3_fail --report report_chk08_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-08   | FAIL   | No QUIC/HTTP3 support indicators found   |
+----------+--------+------------------------------------------+
```

---

## CHK-09: Secure Randomness

### Scenario: Pass (Secure RNG Sources Present)
A binary containing references to secure random number generation sources.
```c
// example_secure_rng_pass.c
#include <stdio.h>
const char* rng_source = "Using /dev/urandom for entropy";
int main() {
    printf("%s\n", rng_source);
    return 0;
}
```
**Compilation**: `gcc example_secure_rng_pass.c -o example_secure_rng_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_secure_rng_pass --report report_chk09_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-09   | PASS   | Secure RNG sources found: ["/dev/urandom"] |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (No Secure RNG Sources)
A binary without references to secure random number generation sources.
```c
// example_secure_rng_fail.c
#include <stdio.h>
const char* rng_source = "Using insecure rand()";
int main() {
    printf("%s\n", rng_source);
    return 0;
}
```
**Compilation**: `gcc example_secure_rng_fail.c -o example_secure_rng_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_secure_rng_fail --report report_chk09_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-09   | FAIL   | No secure randomness sources detected    |
+----------+--------+------------------------------------------+
```

---

## CHK-10: SBOM Generation Capability

### Scenario: Pass (Tool Provides Capability)
This check inherently passes if the `betanet-lint` tool is used, as the tool itself provides SBOM generation capabilities.
```bash
# No specific fixture needed, use any binary
```
**`betanet-lint` Command**:
`cargo run --release -- --binary ./target/release/betanet-lint --report report_chk10_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-10   | PASS   | SBOM generation capability provided by betanet-lint |
+----------+--------+------------------------------------------+
```
**Note**: This check is designed to always pass when `betanet-lint` is the analysis tool.

---

## CHK-11: Specification Version Tags

### Scenario: Pass (Version Tag Present)
A binary containing the `BETANET_SPEC_vX.Y` tag.
```c
// example_version_tag_pass.c
#include <stdio.h>
const char* version_tag = "BETANET_SPEC_v1.0";
int main() {
    printf("%s\n", version_tag);
    return 0;
}
```
**Compilation**: `gcc example_version_tag_pass.c -o example_version_tag_pass`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_version_tag_pass --report report_chk11_pass.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-11   | PASS   | Specification version tags found: ["BETANET_SPEC_v1.0"] |
+----------+--------+------------------------------------------+
```

### Scenario: Fail (No Version Tag)
A binary without the `BETANET_SPEC_vX.Y` tag.
```c
// example_version_tag_fail.c
#include <stdio.h>
int main() {
    printf("No version tag here.\n");
    return 0;
}
```
**Compilation**: `gcc example_version_tag_fail.c -o example_version_tag_fail`

**`betanet-lint` Command**:
`cargo run --release -- --binary ./example_version_tag_fail --report report_chk11_fail.json`
**Expected Output**:
```
+----------+--------+------------------------------------------+
| Check ID | Status | Details                                  |
+----------+--------+------------------------------------------+
| CHK-11   | FAIL   | No BETANET_SPEC_v*.* version tags found  |
+----------+--------+------------------------------------------+