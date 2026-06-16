/*
 * pqc_cert_harness.c
 *
 * Self-signed certificate generation + validation test harness for Windows.
 *
 *   1. Generates a self-signed RSA-3072 / SHA-256 certificate (CNG KSP).
 *   2. Generates a self-signed ML-DSA certificate (FIPS 204, pure mode) for a
 *      chosen parameter set (44 / 65 / 87) via the same CNG certificate path.
 *   3. Validates each with WinVerifyTrust (WTD_CHOICE_CERT, cert trust provider).
 *   4. Cross-checks each with a self-anchored CertGetCertificateChain build,
 *      which actually verifies the (RSA or ML-DSA) self-signature on the cert.
 *   5. Writes each certificate to disk as DER (.der) and PEM (.pem) for
 *      inspection (certutil, openssl, or the Windows cert viewer).
 *
 * Why two validators?
 *   WinVerifyTrust against a *raw* cert uses the system trust stores, so a
 *   self-signed cert that isn't in the machine Root store returns
 *   CERT_E_UNTRUSTEDROOT (0x800B0109). That is the correct, expected outcome --
 *   it proves the trust path ran, not that the cert is broken. To get a clean
 *   positive that genuinely exercises signature verification (including the
 *   ML-DSA self-signature), the harness builds a chain with a private chain
 *   engine whose only trusted root is the cert itself (hExclusiveRoot). That
 *   never touches machine trust and requires no admin rights.
 *
 * Requirements:
 *   - ML-DSA path: Windows 11 24H2 or Windows Server 2025 with the November
 *     2025 update or later (ML-DSA in CNG/wincrypt went GA in that update).
 *     The RSA path runs on any current Windows.
 *   - A Windows SDK with the PQC headers (10.0.26100+) for the BCRYPT_MLDSA_*
 *     symbols. Fallback literals are provided below but are flagged at compile
 *     time -- if key finalize returns NTE_NOT_SUPPORTED on an old-SDK build,
 *     the parameter-set literal is the first thing to check against your SDK.
 *
 * Build (x64 or ARM64 Native Tools / Developer Command Prompt):
 *   cl /W4 /nologo pqc_cert_harness.c /link crypt32.lib ncrypt.lib wintrust.lib
 *
 * Run:
 *   pqc_cert_harness.exe          # RSA-3072 + ML-DSA-65 (default)
 *   pqc_cert_harness.exe 44       # pick ML-DSA parameter set: 44 | 65 | 87
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "wintrust.lib")

 /* ---- ML-DSA CNG constants: prefer the SDK, fall back if headers predate PQC ---- */
#ifndef BCRYPT_MLDSA_ALGORITHM
#pragma message("BCRYPT_MLDSA_ALGORITHM missing from this SDK -- using fallback literal. Update the Windows SDK to 10.0.26100+ and rebuild.")
#define BCRYPT_MLDSA_ALGORITHM        L"ML-DSA"
#endif
#ifndef BCRYPT_PARAMETER_SET_NAME
#define BCRYPT_PARAMETER_SET_NAME     L"ParameterSetName"
#endif
#ifndef BCRYPT_MLDSA_PARAMETER_SET_44
#pragma message("BCRYPT_MLDSA_PARAMETER_SET_* missing -- using fallback literals; verify against your SDK if finalize fails.")
#define BCRYPT_MLDSA_PARAMETER_SET_44 L"44"
#define BCRYPT_MLDSA_PARAMETER_SET_65 L"65"
#define BCRYPT_MLDSA_PARAMETER_SET_87 L"87"
#endif

/* NIST CSOR OIDs for ML-DSA. Parameters MUST be omitted in the
 * AlgorithmIdentifier (each parameter set has its own OID). */
#define szOID_MLDSA_44 "2.16.840.1.101.3.4.3.17"
#define szOID_MLDSA_65 "2.16.840.1.101.3.4.3.18"
#define szOID_MLDSA_87 "2.16.840.1.101.3.4.3.19"

/* ECDSA with SHA-256 signature OID */
#define szOID_ECDSA_SHA256 "1.2.840.10045.4.3.2"

 /* Cert trust provider action GUID used with WTD_CHOICE_CERT
  * (softpub.h: CERT_CERTIFICATE_ACTION_VERIFY). Defined locally for portability. */
static const GUID GUID_CERT_VERIFY =
{ 0x189a3842, 0x3041, 0x11d1, { 0x85, 0xe1, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };

/* ------------------------------------------------------------------------- */

static void PrintErr(const char* what, DWORD code)
{
    LPSTR msg = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, nullptr);
    std::fprintf(stderr, "    %-34s 0x%08lX %s%s",
        what, code, (n && msg) ? msg : "(no system text)",
        (n && msg) ? "" : "\n");
    if (msg) LocalFree(msg);
}

/*
 * Create a self-signed cert from a freshly generated CNG (KSP) key.
 *
 *   pszAlgId    : NCRYPT_RSA_ALGORITHM, NCRYPT_ECDSA_ALGORITHM, or BCRYPT_MLDSA_ALGORITHM
 *   dwRsaBits   : RSA modulus size (ignored when pszParamSet != nullptr or ECDSA)
 *   pszParamSet : ML-DSA parameter set string or ECDSA curve name, or nullptr for RSA
 *   pszSigOid   : signature algorithm OID to stamp into the cert
 *   pwszSubject : X.500 subject DN, e.g. L"CN=Test,O=Lab"
 *
 * Uses an ephemeral key (nullptr key name) plus CERT_CREATE_SELFSIGN_NO_KEY_INFO,
 * so nothing is persisted to the key store and there is nothing to clean up:
 * verification needs only the public cert.
 */
static PCCERT_CONTEXT CreateSelfSigned(
    LPCWSTR pszAlgId, DWORD dwRsaBits, LPCWSTR pszParamSet,
    LPCSTR pszSigOid, LPCWSTR pwszSubject)
{
    SECURITY_STATUS    ss = ERROR_SUCCESS;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey = 0;
    PCCERT_CONTEXT     pCert = nullptr;
    BYTE               nameBuf[1024]{};
    DWORD              nameLen = sizeof(nameBuf);
    CERT_NAME_BLOB     subject{};
    CRYPT_ALGORITHM_IDENTIFIER sigAlg{};

    ss = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (FAILED(ss)) { PrintErr("NCryptOpenStorageProvider", ss); goto done; }

    /* nullptr key name => ephemeral key, not persisted. */
    ss = NCryptCreatePersistedKey(hProv, &hKey, pszAlgId, nullptr, 0, 0);
    if (FAILED(ss)) { PrintErr("NCryptCreatePersistedKey", ss); goto done; }

    if (pszParamSet) {
        /* For ML-DSA: set parameter set. For ECDSA: set curve name. */
        LPCWSTR propName = (wcscmp(pszAlgId, NCRYPT_ECDSA_ALGORITHM) == 0)
            ? NCRYPT_ECC_CURVE_NAME_PROPERTY
            : BCRYPT_PARAMETER_SET_NAME;
        DWORD cb = (DWORD)((wcslen(pszParamSet) + 1) * sizeof(WCHAR));
        ss = NCryptSetProperty(hKey, propName, (PBYTE)pszParamSet, cb, 0);
        if (FAILED(ss)) { PrintErr("NCryptSetProperty(ParameterSet/Curve)", ss); goto done; }
    }
    else {
        /* RSA: set key length */
        ss = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&dwRsaBits, sizeof(dwRsaBits), 0);
        if (FAILED(ss)) { PrintErr("NCryptSetProperty(Length)", ss); goto done; }
    }

    ss = NCryptFinalizeKey(hKey, 0);
    if (FAILED(ss)) { PrintErr("NCryptFinalizeKey", ss); goto done; }

    if (!CertStrToNameW(X509_ASN_ENCODING, pwszSubject, CERT_X500_NAME_STR,
        nullptr, nameBuf, &nameLen, nullptr)) {
        PrintErr("CertStrToName", GetLastError()); goto done;
    }
    subject.pbData = nameBuf;
    subject.cbData = nameLen;

    sigAlg.pszObjId = (LPSTR)pszSigOid;   /* parameters left absent */

    /* nullptr start/end => now .. now + 1 year. */
    pCert = CertCreateSelfSignCertificate(
        hKey, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
        nullptr, &sigAlg, nullptr, nullptr, nullptr);
    if (!pCert) PrintErr("CertCreateSelfSignCertificate", GetLastError());

done:
    if (hKey)  NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return pCert;
}

static void DumpCert(PCCERT_CONTEXT pCert)
{
    char name[256]{};
    CertNameToStrA(X509_ASN_ENCODING, &pCert->pCertInfo->Subject,
        CERT_X500_NAME_STR, name, sizeof(name));
    std::printf("    subject            : %s\n", name);
    std::printf("    signature alg OID  : %s\n",
        pCert->pCertInfo->SignatureAlgorithm.pszObjId);
}

/*
 * Write the certificate to "<base>.der" (raw DER). Inspect with, e.g.:
 *   certutil -dump <base>.der          (Windows)
 *   certutil -asn  <base>.der          (raw ASN.1 tree)
 * The .der also opens directly in the Windows certificate viewer.
 */
static BOOL WriteCertFiles(PCCERT_CONTEXT pCert, const char* base)
{
    char   path[MAX_PATH]{};
    BOOL   ok = FALSE;
    DWORD  written = 0;
    HANDLE h = INVALID_HANDLE_VALUE;

    /* DER: the raw encoded certificate bytes. */
    std::sprintf(path, "%s.der", base);
    h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { PrintErr("CreateFile(.der)", GetLastError()); goto done; }
    if (!WriteFile(h, pCert->pbCertEncoded, pCert->cbCertEncoded, &written, nullptr) ||
        written != pCert->cbCertEncoded) {
        PrintErr("WriteFile(.der)", GetLastError()); CloseHandle(h); goto done;
    }
    CloseHandle(h);
    ok = TRUE;

done:
    return ok;
}

static const char* ChainErrorText(DWORD dwErrorStatus)
{
    if (dwErrorStatus == CERT_TRUST_NO_ERROR)
        return "no error";
    if (dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID)
        return "certificate or issuer expired/not yet valid";
    if (dwErrorStatus & CERT_TRUST_IS_NOT_TIME_NESTED)
        return "validity period nesting incorrect";
    if (dwErrorStatus & CERT_TRUST_IS_REVOKED)
        return "certificate revoked";
    if (dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
        return "signature invalid";
    if (dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
        return "certificate not valid for requested usage";
    if (dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
        return "root certificate not trusted";
    if (dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
        return "revocation status unknown";
    if (dwErrorStatus & CERT_TRUST_IS_CYCLIC)
        return "cyclic chain detected";
    if (dwErrorStatus & CERT_TRUST_INVALID_EXTENSION)
        return "invalid extension";
    if (dwErrorStatus & CERT_TRUST_INVALID_POLICY_CONSTRAINTS)
        return "invalid policy constraints";
    if (dwErrorStatus & CERT_TRUST_INVALID_BASIC_CONSTRAINTS)
        return "invalid basic constraints";
    if (dwErrorStatus & CERT_TRUST_INVALID_NAME_CONSTRAINTS)
        return "invalid name constraints";
    if (dwErrorStatus & CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT)
        return "unsupported name constraint";
    if (dwErrorStatus & CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT)
        return "undefined name constraint";
    if (dwErrorStatus & CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT)
        return "not permitted name constraint";
    if (dwErrorStatus & CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT)
        return "excluded name constraint";
    if (dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN)
        return "partial chain";
    if (dwErrorStatus & CERT_TRUST_CTL_IS_NOT_TIME_VALID)
        return "CTL expired/not yet valid";
    if (dwErrorStatus & CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID)
        return "CTL signature invalid";
    if (dwErrorStatus & CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE)
        return "CTL not valid for usage";
    return "see error code above";
}

static const char* WvtText(LONG s)
{
    switch ((DWORD)s) {
        case 0:                                  return "trusted";
        case (DWORD)CERT_E_UNTRUSTEDROOT:        return "untrusted root (expected: self-signed, not in Root store)";
        case (DWORD)CERT_E_EXPIRED:              return "expired";
        case (DWORD)CERT_E_CHAINING:             return "chaining error";
        case (DWORD)TRUST_E_SUBJECT_NOT_TRUSTED: return "subject not trusted";
        case (DWORD)TRUST_E_NOSIGNATURE:         return "no/invalid signature";
        default:                                 return "see HRESULT above";
    }
}

/* Verify a raw cert through WinVerifyTrust's certificate trust provider. */
static LONG CheckWinVerifyTrust(PCCERT_CONTEXT pCert)
{
    WINTRUST_CERT_INFO ci{};
    ci.cbStruct = sizeof(ci);
    ci.psCertContext = (PCERT_CONTEXT)pCert;

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CERT;
    wd.pCert = &ci;
    wd.dwStateAction = WTD_STATEACTION_IGNORE;

    GUID action = GUID_CERT_VERIFY;
    return WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
}

/*
 * Build a chain that trusts ONLY the cert itself as its root, then run the
 * base policy. This verifies the self-signature (RSA or ML-DSA) without
 * modifying any machine trust store.
 */
static BOOL VerifySelfAnchored(PCCERT_CONTEXT pCert)
{
    BOOL                     ok = FALSE;
    HCERTSTORE               hRoot = nullptr;
    HCERTCHAINENGINE         hEngine = nullptr;
    PCCERT_CHAIN_CONTEXT     pChain = nullptr;
    CERT_CHAIN_ENGINE_CONFIG cfg{};
    CERT_CHAIN_PARA          para{};
    CERT_CHAIN_POLICY_PARA   polPara{};
    CERT_CHAIN_POLICY_STATUS polStat{};

    hRoot = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, 0, 0, nullptr);
    if (!hRoot) { PrintErr("CertOpenStore", GetLastError()); goto done; }

    if (!CertAddCertificateContextToStore(hRoot, pCert,
        CERT_STORE_ADD_ALWAYS, nullptr)) {
        PrintErr("CertAddCertificateContextToStore", GetLastError()); goto done;
    }

    cfg.cbSize = sizeof(cfg);
    cfg.hExclusiveRoot = hRoot;   /* the only trusted root is our own cert */
    if (!CertCreateCertificateChainEngine(&cfg, &hEngine)) {
        PrintErr("CertCreateCertificateChainEngine", GetLastError()); goto done;
    }

    para.cbSize = sizeof(para);
    if (!CertGetCertificateChain(hEngine, pCert, nullptr, nullptr, &para,
        0, nullptr, &pChain)) {
        PrintErr("CertGetCertificateChain", GetLastError()); goto done;
    }

    std::printf("    chain error status : 0x%08lX (%s)\n", 
        pChain->TrustStatus.dwErrorStatus, 
        ChainErrorText(pChain->TrustStatus.dwErrorStatus));

    polPara.cbSize = sizeof(polPara);
    polStat.cbSize = sizeof(polStat);
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChain,
        &polPara, &polStat)) {
        PrintErr("CertVerifyCertificateChainPolicy", GetLastError()); goto done;
    }

    if (polStat.dwError == 0 &&
        pChain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
        ok = TRUE;
    }
    else {
        std::printf("    base policy error  : 0x%08lX\n", polStat.dwError);
    }

done:
    if (pChain)  CertFreeCertificateChain(pChain);
    if (hEngine) CertFreeCertificateChainEngine(hEngine);
    if (hRoot)   CertCloseStore(hRoot, 0);
    return ok;
}

static int RunTest(const char* label, const char* fileBase,
    LPCWSTR alg, DWORD rsaBits,
    LPCWSTR paramSet, LPCSTR sigOid, LPCWSTR subject)
{
    std::printf("== %s ==\n", label);

    auto pCert = CreateSelfSigned(alg, rsaBits, paramSet, sigOid, subject);
    if (!pCert) {
        std::printf("    RESULT: FAIL (certificate not created)\n\n");
        return 1;
    }
    DumpCert(pCert);
    WriteCertFiles(pCert, fileBase);

    LONG wvt = CheckWinVerifyTrust(pCert);
    std::printf("    WinVerifyTrust     : 0x%08lX (%s)\n", (DWORD)wvt, WvtText(wvt));

    BOOL anchored = VerifySelfAnchored(pCert);
    std::printf("    self-anchored chain: %s\n",
        anchored ? "VALID (self-signature verified)" : "INVALID");

    /* Pass: cert built, self-signature verifies under self-anchor, and WVT
     * reached a verdict (trusted, or untrusted-root as expected). */
    int pass = anchored &&
        (wvt == 0 || (DWORD)wvt == (DWORD)CERT_E_UNTRUSTEDROOT);
    std::printf("    RESULT: %s\n\n", pass ? "PASS" : "FAIL");

    CertFreeCertificateContext(pCert);
    return pass ? 0 : 1;
}

int main(int argc, char** argv)
{
    const char* want = (argc > 1) ? argv[1] : "65";
    LPCWSTR pset = nullptr;
    LPCSTR  poid = nullptr;
    char mldsaBase[64]{};
    int rc = 0;

    if (!std::strcmp(want, "44")) { pset = BCRYPT_MLDSA_PARAMETER_SET_44; poid = szOID_MLDSA_44; }
    else if (!std::strcmp(want, "87")) { pset = BCRYPT_MLDSA_PARAMETER_SET_87; poid = szOID_MLDSA_87; }
    else { pset = BCRYPT_MLDSA_PARAMETER_SET_65; poid = szOID_MLDSA_65; want = "65"; }

    std::sprintf(mldsaBase, "mldsa%s_selfsigned", want);

    std::printf("Self-signed certificate validation harness (built %s)\n", __DATE__);
    std::printf("ML-DSA parameter set: ML-DSA-%s\n\n", want);

    rc |= RunTest("RSA-3072 / SHA-256", "rsa3072_selfsigned",
        NCRYPT_RSA_ALGORITHM, 3072, nullptr,
        szOID_RSA_SHA256RSA, L"CN=RSA Self-Signed Test,O=Harness");

    rc |= RunTest("ECDSA-P256 / SHA-256", "ecdsap256_selfsigned",
        NCRYPT_ECDSA_ALGORITHM, 0, BCRYPT_ECC_CURVE_NISTP256,
        szOID_ECDSA_SHA256, L"CN=ECDSA Self-Signed Test,O=Harness");

    rc |= RunTest("ML-DSA (pure)", mldsaBase,
        BCRYPT_MLDSA_ALGORITHM, 0, pset,
        poid, L"CN=ML-DSA Self-Signed Test,O=Harness");

    std::printf("Overall: %s\n", rc == 0 ? "ALL TESTS PASSED" : "ONE OR MORE TESTS FAILED");
    return rc;
}
