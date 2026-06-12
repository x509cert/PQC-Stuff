# WinVerifyTrust() pqc-cert-harness

A small Windows test harness in C that generates self-signed **RSA** and
**ML-DSA** (FIPS 204) certificates and validates each one two ways:
through **WinVerifyTrust** and through a **self-anchored certificate chain
build**. It also writes every certificate to disk as DER and PEM so you can
inspect the encoding.

It's meant as a minimal, readable reference for exercising post-quantum
certificate support on the modern Windows crypto stack (CNG / wincrypt),
alongside the classical RSA path for comparison.

## What it does

For each algorithm the harness:

1. Generates a key with a CNG Key Storage Provider (ephemeral, not persisted).
2. Builds a self-signed certificate with `CertCreateSelfSignCertificate`.
3. Validates the raw certificate with `WinVerifyTrust` (`WTD_CHOICE_CERT`).
4. Verifies the self-signature with a private chain engine that trusts only
   the certificate itself as its root (`hExclusiveRoot`).
5. Writes `<name>.der` and `<name>.pem`.

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
| Compiler | MSVC (`cl`) from Visual Studio or the Build Tools. |

Fallback `#define`s for the ML-DSA constants are included so the code still
compiles on a slightly older SDK, but building against the real SDK macros is
strongly preferred — see [Troubleshooting](#troubleshooting).

## Build

From an **x64 Native Tools Command Prompt** (or any Developer Command Prompt):

```bat
cl /W4 /nologo pqc_cert_harness.c /link crypt32.lib ncrypt.lib wintrust.lib
```

## Usage

```bat
pqc_cert_harness.exe          :: RSA-3072 + ML-DSA-65 (default)
pqc_cert_harness.exe 44       :: choose the ML-DSA parameter set: 44 | 65 | 87
```

### Example output

```
Self-signed certificate validation harness (built <date>)
ML-DSA parameter set: ML-DSA-65

== RSA-3072 / SHA-256 ==
    subject            : CN=RSA Self-Signed Test, O=Harness
    signature alg OID  : 1.2.840.113549.1.1.11
    public key alg OID : 1.2.840.113549.1.1.1
    public key bytes   : 398
    encoded cert bytes : 712
    wrote              : rsa3072_selfsigned.der (712 bytes, DER)
    wrote              : rsa3072_selfsigned.pem (PEM)
    WinVerifyTrust     : 0x800B0109 (untrusted root (expected: self-signed, not in Root store))
    chain error status : 0x00000000
    self-anchored chain: VALID (self-signature verified)
    RESULT: PASS

== ML-DSA (pure) ==
    subject            : CN=ML-DSA Self-Signed Test, O=Harness
    signature alg OID  : 2.16.840.1.101.3.4.3.18
    public key alg OID : 2.16.840.1.101.3.4.3.18
    public key bytes   : 1952
    encoded cert bytes : ...
    wrote              : mldsa65_selfsigned.der (... bytes, DER)
    wrote              : mldsa65_selfsigned.pem (PEM)
    WinVerifyTrust     : 0x800B0109 (untrusted root (expected: self-signed, not in Root store))
    chain error status : 0x00000000
    self-anchored chain: VALID (self-signature verified)
    RESULT: PASS

Overall: ALL TESTS PASSED
```

(Exact byte counts vary; the values above are illustrative.)

## Output files

Each run (over)writes, in the working directory:

| File | Contents |
|------|----------|
| `rsa3072_selfsigned.der` / `.pem` | RSA-3072 / SHA-256 certificate |
| `mldsa<set>_selfsigned.der` / `.pem` | ML-DSA certificate for the selected parameter set |

The certificates are public-only: keys are ephemeral and never written to
disk, so the files are safe to share, commit, or diff. (No private key, no PFX.)

### Inspecting the certificates

```bat
certutil -dump  mldsa65_selfsigned.der            :: human-readable summary
certutil -asn   mldsa65_selfsigned.der            :: raw ASN.1 tree
```

```bash
openssl x509 -in mldsa65_selfsigned.pem -text -noout
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

## ML-DSA reference

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

Everything lives in a single file, `pqc_cert_harness.c`:

- `create_self_signed()` — KSP key generation + `CertCreateSelfSignCertificate`
  (ephemeral key, `CERT_CREATE_SELFSIGN_NO_KEY_INFO`).
- `write_cert_files()` — DER + PEM output (`CryptBinaryToStringA`).
- `verify_winverifytrust()` — `WTD_CHOICE_CERT` path.
- `verify_self_anchored()` — private chain engine with `hExclusiveRoot`.
- `run_test()` / `main()` — drive both algorithms and summarize.

## License

Add your preferred license here (e.g. MIT).

## Disclaimer

Test/diagnostic code. The certificates it produces are throwaway, self-signed,
and use ephemeral keys. Don't use them for anything real.
