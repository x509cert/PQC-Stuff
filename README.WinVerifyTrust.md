# WinVerifyTrust - PQC Certificate Harness

A Windows test harness in modern C++ that generates self-signed **RSA**, **ECDSA**, and
**ML-DSA** (FIPS 204) certificates and validates each one two ways:
through **WinVerifyTrust** and through a **self-anchored certificate chain
build**. It also writes every certificate to disk as DER for inspection.

It's meant as a minimal, readable reference for exercising post-quantum
certificate support on the modern Windows crypto stack (CNG / wincrypt),
alongside classical signature algorithms (RSA, ECDSA) for comparison. The codebase uses modern C++
constructs including nullptr, brace initialization, auto, inline declarations,
and PascalCase function naming.

## What it does

For each algorithm the harness:

1. Generates a key with a CNG Key Storage Provider (ephemeral, not persisted).
2. Builds a self-signed certificate with `CertCreateSelfSignCertificate`.
3. Validates the raw certificate with `WinVerifyTrust` (`WTD_CHOICE_CERT`) via `CheckWinVerifyTrust()`.
4. Verifies the self-signature with a private chain engine that trusts only
   the certificate itself as its root (`hExclusiveRoot`) via `VerifySelfAnchored()`.
5. Writes `<name>.der` (DER format only).

### Why two validators

`WinVerifyTrust` on a *raw* certificate uses the machine trust stores, so a
self-signed certificate that isn't installed in the Root store returns
`CERT_E_UNTRUSTEDROOT` (`0x800B0109`). That is the **expected** result — it
proves the trust path executed, not that the certificate is broken.

To get a clean positive that genuinely verifies the signature (including the
ML-DSA self-signature), the harness builds a chain with a private chain engine
whose only trusted root is the certificate itself. This requires no admin
rights and touches no machine state. A run is treated as **PASS** when the
self-anchored chain is valid *and* `WinVerifyTrust` returned either trusted or
the expected untrusted-root verdict.

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS (ML-DSA path) | Windows 11 24H2 **or** Windows Server 2025, with the **November 2025 update** or later. ML-DSA in CNG/wincrypt went GA in that update. |
| OS (RSA path) | Any current Windows. |
| SDK | Windows SDK **10.0.26100** or later, for the `BCRYPT_MLDSA_*` symbols. |
| Compiler | MSVC (`cl`) from Visual Studio 2019 or later (C++17 support required for modern constructs). |

Fallback `#define`s for the ML-DSA constants are included so the code still
compiles on a slightly older SDK, but building against the real SDK macros is
strongly preferred — see [Troubleshooting](#troubleshooting).

## Build

From an **x64 Native Tools Command Prompt** (or any Developer Command Prompt) or Visual Studio:

```bat
cl /W4 /nologo /std:c++17 WinVerifyTrust.cpp /link crypt32.lib ncrypt.lib wintrust.lib
```

Or open `WinVerifyTrust.vcxproj` in Visual Studio and build normally.

## Usage

```bat
WinVerifyTrust.exe          :: RSA-3072 + ML-DSA-65 (default)
WinVerifyTrust.exe 44       :: choose the ML-DSA parameter set: 44 | 65 | 87
```

### Example output

```
Self-signed certificate validation harness (built <date>)
ML-DSA parameter set: ML-DSA-65

== RSA-3072 / SHA-256 ==
    subject            : CN=RSA Self-Signed Test, O=Harness
    signature alg OID  : 1.2.840.113549.1.1.11
    WinVerifyTrust     : 0x800B0109 (untrusted root (expected: self-signed, not in Root store))
    chain error status : 0x00000000 (no error)
    self-anchored chain: VALID (self-signature verified)
    RESULT: PASS

== ECDSA-P256 / SHA-256 ==
    subject            : CN=ECDSA Self-Signed Test, O=Harness
    signature alg OID  : 1.2.840.10045.4.3.2
    WinVerifyTrust     : 0x800B0109 (untrusted root (expected: self-signed, not in Root store))
    chain error status : 0x00000000 (no error)
    self-anchored chain: VALID (self-signature verified)
    RESULT: PASS

== ML-DSA (pure) ==
    subject            : CN=ML-DSA Self-Signed Test, O=Harness
    signature alg OID  : 2.16.840.1.101.3.4.3.18
    WinVerifyTrust     : 0x800B0109 (untrusted root (expected: self-signed, not in Root store))
    chain error status : 0x00000000 (no error)
    self-anchored chain: VALID (self-signature verified)
    RESULT: PASS

Overall: ALL TESTS PASSED
```

## Output files

Each run (over)writes, in the working directory:

| File | Contents |
|------|----------|
| `rsa3072_selfsigned.der` | RSA-3072 / SHA-256 certificate (DER format) |
| `ecdsap256_selfsigned.der` | ECDSA-P256 / SHA-256 certificate (DER format) |
| `mldsa<set>_selfsigned.der` | ML-DSA certificate for the selected parameter set (DER format) |

The certificates are public-only: keys are ephemeral and never written to
disk, so the files are safe to share, commit, or diff. (No private key, no PFX.)

### Inspecting the certificates

```bat
certutil -dump  mldsa65_selfsigned.der            :: human-readable summary
certutil -asn   mldsa65_selfsigned.der            :: raw ASN.1 tree
```

The `.der` file also opens directly in the Windows certificate viewer on
double-click.

For the ML-DSA certificates, the structure worth checking:

- The signature `AlgorithmIdentifier` and the SPKI algorithm both carry the
  ML-DSA OID with **no `parameters` field** (each parameter set has its own OID).
- The SPKI `subjectPublicKey` `BIT STRING` length matches the parameter set.

A current `certutil` is the more reliable reader for PQC certificates; older
`openssl` builds without ML-DSA OID tables parse the structure but print the
algorithm as an unrecognized OID instead of a friendly name.

## Code Style

The codebase uses modern C++ constructs compatible with C++17:

- **nullptr** instead of `NULL` for pointer initialization
- **Brace initialization** (`{}`) for zero-initialization of structs and arrays
- **auto** keyword for type deduction where appropriate
- **Inline variable declarations** closer to point of use
- **std:: namespace** for C library functions (`std::printf`, `std::sprintf`, `std::strcmp`, `std::fprintf`)
- **PascalCase function names** for consistency (e.g., `CreateSelfSigned()`, `CheckWinVerifyTrust()`)
- **Explicit initialization** for safer defaults (e.g., `HANDLE h = INVALID_HANDLE_VALUE`)

This makes the code more robust and easier to maintain while remaining compatible
with Windows crypto APIs.

## Algorithm Reference

### ECDSA

This harness tests **ECDSA-P256** (secp256r1 / prime256v1) with SHA-256:

| Property | Value |
|----------|-------|
| Curve | NIST P-256 (secp256r1) |
| Signature OID | `1.2.840.10045.4.3.2` (ecdsa-with-SHA256) |
| Public key size | 65 bytes (uncompressed point) |
| Security level | ~128-bit classical |

ECDSA is widely supported across all modern Windows versions and provides
efficient signatures with smaller key sizes compared to RSA.

### ML-DSA

NIST CSOR object identifiers (parameters omitted in the `AlgorithmIdentifier`):

| Parameter set | NIST level | OID | Public key (bytes) | Signature (bytes) |
|---------------|-----------|-----|--------------------|-------------------|
| ML-DSA-44 | 2 | `2.16.840.1.101.3.4.3.17` | 1312 | 2420 |
| ML-DSA-65 | 3 | `2.16.840.1.101.3.4.3.18` | 1952 | 3309 |
| ML-DSA-87 | 5 | `2.16.840.1.101.3.4.3.19` | 2592 | 4627 |

ML-DSA is signature-only and is exposed through CNG Key Storage Providers (not
legacy CSPs). This harness uses the pure variant.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Compile error: `BCRYPT_MLDSA_ALGORITHM` / `BCRYPT_MLDSA_PARAMETER_SET_*` undefined | Windows SDK predates PQC support. The fallback `#define`s let it compile, but update to SDK 10.0.26100+ for the official literals. |
| `NCryptFinalizeKey` returns `NTE_NOT_SUPPORTED` (`0x80090029`) on the ML-DSA test | Runtime lacks ML-DSA (OS not on the Nov 2025 update), **or** a fallback parameter-set literal doesn't match your SDK. Check the literal first. |
| `NCryptCreatePersistedKey` returns `NTE_BAD_ALGID` (`0x80090008`) | The build doesn't expose `ML-DSA` in CNG. Confirm the OS version. |
| `CertCreateSelfSignCertificate` fails only for ML-DSA | wincrypt OID-to-signing mapping not present — OS build too old. |
| `WinVerifyTrust` returns `0x800B0109` | Expected for a self-signed cert not in the Root store. Not a failure. |

## How it works (source layout)

Everything lives in a single file, `WinVerifyTrust.cpp`:

- `CreateSelfSigned()` — KSP key generation + `CertCreateSelfSignCertificate`
  (ephemeral key, `CERT_CREATE_SELFSIGN_NO_KEY_INFO`). Handles RSA, ECDSA, and ML-DSA.
- `WriteCertFiles()` — DER output to disk.
- `CheckWinVerifyTrust()` — `WTD_CHOICE_CERT` path for trust validation.
- `VerifySelfAnchored()` — private chain engine with `hExclusiveRoot` for signature verification.
- `DumpCert()` — display certificate subject and signature algorithm.
- `RunTest()` / `main()` — drive all three algorithms and summarize results.
- `PrintErr()` — formatted error output with system messages.
- `ChainErrorText()` — translate certificate chain error status codes to readable text.
- `WvtText()` — translate WinVerifyTrust return codes to readable text.

## License

Add your preferred license here (e.g. MIT).

## Disclaimer

Test/diagnostic code. The certificates it produces are throwaway, self-signed,
and use ephemeral keys. Don't use them for anything real.
