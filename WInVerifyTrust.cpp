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
 * Build (x64 Native Tools / Developer Command Prompt):
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
#include <stdio.h>
#include <string.h>

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

 /* Cert trust provider action GUID used with WTD_CHOICE_CERT
  * (softpub.h: CERT_CERTIFICATE_ACTION_VERIFY). Defined locally for portability. */
static const GUID GUID_CERT_VERIFY =
{ 0x189a3842, 0x3041, 0x11d1, { 0x85, 0xe1, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };

/* ------------------------------------------------------------------------- */

static void print_err(const char* what, DWORD code)
{
    LPSTR msg = NULL;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
    fprintf(stderr, "    %-34s 0x%08lX %s%s",
        what, code, (n && msg) ? msg : "(no system text)",
        (n && msg) ? "" : "\n");
    if (msg) LocalFree(msg);
}

/*
 * Create a self-signed cert from a freshly generated CNG (KSP) key.
 *
 *   pszAlgId    : NCRYPT_RSA_ALGORITHM or BCRYPT_MLDSA_ALGORITHM
 *   dwRsaBits   : RSA modulus size (ignored when pszParamSet != NULL)
 *   pszParamSet : ML-DSA parameter set string, or NULL for RSA
 *   pszSigOid   : signature algorithm OID to stamp into the cert
 *   pwszSubject : X.500 subject DN, e.g. L"CN=Test,O=Lab"
 *
 * Uses an ephemeral key (NULL key name) plus CERT_CREATE_SELFSIGN_NO_KEY_INFO,
 * so nothing is persisted to the key store and there is nothing to clean up:
 * verification needs only the public cert.
 */
static PCCERT_CONTEXT create_self_signed(
    LPCWSTR pszAlgId, DWORD dwRsaBits, LPCWSTR pszParamSet,
    LPCSTR pszSigOid, LPCWSTR pwszSubject)
{
    SECURITY_STATUS    ss;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey = 0;
    PCCERT_CONTEXT     pCert = NULL;
    BYTE               nameBuf[1024];
    DWORD              nameLen = sizeof(nameBuf);
    CERT_NAME_BLOB     subject = { 0 };
    CRYPT_ALGORITHM_IDENTIFIER sigAlg = { 0 };

    ss = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (FAILED(ss)) { print_err("NCryptOpenStorageProvider", ss); goto done; }

    /* NULL key name => ephemeral key, not persisted. */
    ss = NCryptCreatePersistedKey(hProv, &hKey, pszAlgId, NULL, 0, 0);
    if (FAILED(ss)) { print_err("NCryptCreatePersistedKey", ss); goto done; }

    if (pszParamSet) {
        DWORD cb = (DWORD)((wcslen(pszParamSet) + 1) * sizeof(WCHAR));
        ss = NCryptSetProperty(hKey, BCRYPT_PARAMETER_SET_NAME,
            (PBYTE)pszParamSet, cb, 0);
        if (FAILED(ss)) { print_err("NCryptSetProperty(ParameterSet)", ss); goto done; }
    }
    else {
        ss = NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&dwRsaBits, sizeof(dwRsaBits), 0);
        if (FAILED(ss)) { print_err("NCryptSetProperty(Length)", ss); goto done; }
    }

    ss = NCryptFinalizeKey(hKey, 0);
    if (FAILED(ss)) { print_err("NCryptFinalizeKey", ss); goto done; }

    if (!CertStrToNameW(X509_ASN_ENCODING, pwszSubject, CERT_X500_NAME_STR,
        NULL, nameBuf, &nameLen, NULL)) {
        print_err("CertStrToName", GetLastError()); goto done;
    }
    subject.pbData = nameBuf;
    subject.cbData = nameLen;

    sigAlg.pszObjId = (LPSTR)pszSigOid;   /* parameters left absent */

    /* NULL start/end => now .. now + 1 year. */
    pCert = CertCreateSelfSignCertificate(
        hKey, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
        NULL, &sigAlg, NULL, NULL, NULL);
    if (!pCert) print_err("CertCreateSelfSignCertificate", GetLastError());

done:
    if (hKey)  NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return pCert;
}

static void dump_cert(PCCERT_CONTEXT pCert)
{
    char name[256] = { 0 };
    CertNameToStrA(X509_ASN_ENCODING, &pCert->pCertInfo->Subject,
        CERT_X500_NAME_STR, name, sizeof(name));
    printf("    subject            : %s\n", name);
    printf("    signature alg OID  : %s\n",
        pCert->pCertInfo->SignatureAlgorithm.pszObjId);
    printf("    public key alg OID : %s\n",
        pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    printf("    public key bytes   : %lu\n",
        pCert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);
    printf("    encoded cert bytes : %lu\n", pCert->cbCertEncoded);
}

/*
 * Write the certificate to "<base>.der" (raw DER) and "<base>.pem" (base64 with
 * -----BEGIN CERTIFICATE----- header). Inspect with, e.g.:
 *   certutil -dump <base>.der          (Windows)
 *   certutil -asn  <base>.der          (raw ASN.1 tree)
 *   openssl x509 -in <base>.pem -text -noout
 * The .der also opens directly in the Windows certificate viewer.
 */
static BOOL write_cert_files(PCCERT_CONTEXT pCert, const char* base)
{
    char   path[MAX_PATH];
    BOOL   ok = FALSE;
    DWORD  written = 0;
    HANDLE h;
    LPSTR  pem = NULL;
    DWORD  pemChars = 0;

    /* DER: the raw encoded certificate bytes. */
    sprintf(path, "%s.der", base);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { print_err("CreateFile(.der)", GetLastError()); goto done; }
    if (!WriteFile(h, pCert->pbCertEncoded, pCert->cbCertEncoded, &written, NULL) ||
        written != pCert->cbCertEncoded) {
        print_err("WriteFile(.der)", GetLastError()); CloseHandle(h); goto done;
    }
    CloseHandle(h);
    printf("    wrote              : %s (%lu bytes, DER)\n", path, pCert->cbCertEncoded);

    /* PEM: base64 of the same DER, wrapped with BEGIN/END CERTIFICATE. */
    if (!CryptBinaryToStringA(pCert->pbCertEncoded, pCert->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER, NULL, &pemChars)) {
        print_err("CryptBinaryToStringA(size)", GetLastError()); goto done;
    }
    pem = (LPSTR)LocalAlloc(LMEM_FIXED, pemChars);
    if (!pem) { print_err("LocalAlloc(pem)", GetLastError()); goto done; }
    if (!CryptBinaryToStringA(pCert->pbCertEncoded, pCert->cbCertEncoded,
        CRYPT_STRING_BASE64HEADER, pem, &pemChars)) {
        print_err("CryptBinaryToStringA", GetLastError()); goto done;
    }

    sprintf(path, "%s.pem", base);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { print_err("CreateFile(.pem)", GetLastError()); goto done; }
    if (!WriteFile(h, pem, (DWORD)strlen(pem), &written, NULL)) {
        print_err("WriteFile(.pem)", GetLastError()); CloseHandle(h); goto done;
    }
    CloseHandle(h);
    printf("    wrote              : %s (PEM)\n", path);
    ok = TRUE;

done:
    if (pem) LocalFree(pem);
    return ok;
}

static const char* wvt_text(LONG s)
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
static LONG verify_winverifytrust(PCCERT_CONTEXT pCert)
{
    WINTRUST_CERT_INFO ci = { 0 };
    WINTRUST_DATA      wd = { 0 };
    GUID action = GUID_CERT_VERIFY;

    ci.cbStruct = sizeof(ci);
    ci.psCertContext = (PCERT_CONTEXT)pCert;

    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CERT;
    wd.pCert = &ci;
    wd.dwStateAction = WTD_STATEACTION_IGNORE;

    return WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
}

/*
 * Build a chain that trusts ONLY the cert itself as its root, then run the
 * base policy. This verifies the self-signature (RSA or ML-DSA) without
 * modifying any machine trust store.
 */
static BOOL verify_self_anchored(PCCERT_CONTEXT pCert)
{
    BOOL                     ok = FALSE;
    HCERTSTORE               hRoot = NULL;
    HCERTCHAINENGINE         hEngine = NULL;
    PCCERT_CHAIN_CONTEXT     pChain = NULL;
    CERT_CHAIN_ENGINE_CONFIG cfg = { 0 };
    CERT_CHAIN_PARA          para = { 0 };
    CERT_CHAIN_POLICY_PARA   polPara = { 0 };
    CERT_CHAIN_POLICY_STATUS polStat = { 0 };

    hRoot = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, 0, 0, NULL);
    if (!hRoot) { print_err("CertOpenStore", GetLastError()); goto done; }

    if (!CertAddCertificateContextToStore(hRoot, pCert,
        CERT_STORE_ADD_ALWAYS, NULL)) {
        print_err("CertAddCertificateContextToStore", GetLastError()); goto done;
    }

    cfg.cbSize = sizeof(cfg);
    cfg.hExclusiveRoot = hRoot;   /* the only trusted root is our own cert */
    if (!CertCreateCertificateChainEngine(&cfg, &hEngine)) {
        print_err("CertCreateCertificateChainEngine", GetLastError()); goto done;
    }

    para.cbSize = sizeof(para);
    if (!CertGetCertificateChain(hEngine, pCert, NULL, NULL, &para,
        0, NULL, &pChain)) {
        print_err("CertGetCertificateChain", GetLastError()); goto done;
    }

    printf("    chain error status : 0x%08lX\n", pChain->TrustStatus.dwErrorStatus);

    polPara.cbSize = sizeof(polPara);
    polStat.cbSize = sizeof(polStat);
    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChain,
        &polPara, &polStat)) {
        print_err("CertVerifyCertificateChainPolicy", GetLastError()); goto done;
    }

    if (polStat.dwError == 0 &&
        pChain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR) {
        ok = TRUE;
    }
    else {
        printf("    base policy error  : 0x%08lX\n", polStat.dwError);
    }

done:
    if (pChain)  CertFreeCertificateChain(pChain);
    if (hEngine) CertFreeCertificateChainEngine(hEngine);
    if (hRoot)   CertCloseStore(hRoot, 0);
    return ok;
}

static int run_test(const char* label, const char* fileBase,
    LPCWSTR alg, DWORD rsaBits,
    LPCWSTR paramSet, LPCSTR sigOid, LPCWSTR subject)
{
    int pass;
    LONG wvt;
    BOOL anchored;
    PCCERT_CONTEXT pCert;

    printf("== %s ==\n", label);

    pCert = create_self_signed(alg, rsaBits, paramSet, sigOid, subject);
    if (!pCert) {
        printf("    RESULT: FAIL (certificate not created)\n\n");
        return 1;
    }
    dump_cert(pCert);
    write_cert_files(pCert, fileBase);

    wvt = verify_winverifytrust(pCert);
    printf("    WinVerifyTrust     : 0x%08lX (%s)\n", (DWORD)wvt, wvt_text(wvt));

    anchored = verify_self_anchored(pCert);
    printf("    self-anchored chain: %s\n",
        anchored ? "VALID (self-signature verified)" : "INVALID");

    /* Pass: cert built, self-signature verifies under self-anchor, and WVT
     * reached a verdict (trusted, or untrusted-root as expected). */
    pass = anchored &&
        (wvt == 0 || (DWORD)wvt == (DWORD)CERT_E_UNTRUSTEDROOT);
    printf("    RESULT: %s\n\n", pass ? "PASS" : "FAIL");

    CertFreeCertificateContext(pCert);
    return pass ? 0 : 1;
}

int main(int argc, char** argv)
{
    const char* want = (argc > 1) ? argv[1] : "65";
    LPCWSTR pset;
    LPCSTR  poid;
    char mldsaBase[64];
    int rc = 0;

    if (!strcmp(want, "44")) { pset = BCRYPT_MLDSA_PARAMETER_SET_44; poid = szOID_MLDSA_44; }
    else if (!strcmp(want, "87")) { pset = BCRYPT_MLDSA_PARAMETER_SET_87; poid = szOID_MLDSA_87; }
    else { pset = BCRYPT_MLDSA_PARAMETER_SET_65; poid = szOID_MLDSA_65; want = "65"; }

    sprintf(mldsaBase, "mldsa%s_selfsigned", want);

    printf("Self-signed certificate validation harness (built %s)\n", __DATE__);
    printf("ML-DSA parameter set: ML-DSA-%s\n\n", want);

    rc |= run_test("RSA-3072 / SHA-256", "rsa3072_selfsigned",
        NCRYPT_RSA_ALGORITHM, 3072, NULL,
        szOID_RSA_SHA256RSA, L"CN=RSA Self-Signed Test,O=Harness");

    rc |= run_test("ML-DSA (pure)", mldsaBase,
        BCRYPT_MLDSA_ALGORITHM, 0, pset,
        poid, L"CN=ML-DSA Self-Signed Test,O=Harness");

    printf("Overall: %s\n", rc == 0 ? "ALL TESTS PASSED" : "ONE OR MORE TESTS FAILED");
    return rc;
}