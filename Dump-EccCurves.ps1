# Requires admin
# TLS ECC Curve Inspection + Modify + Rollback

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
$regName = "EccCurves"
$curveToTest = "X25519_MLKEM768"

function Dump-State {
    param([string]$phase)

    Write-Host "`n==================== $phase ====================" -ForegroundColor Cyan

    Write-Host "`n[+] PowerShell View (Get-TlsEccCurve)"
    try {
        Get-TlsEccCurve
    } catch {
        Write-Warning "Get-TlsEccCurve failed: $_"
    }

    Write-Host "`n[+] Registry View ($regPath\$regName)"
    try {
        $val = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
        if ($val) {
            $val
        } else {
            Write-Host "(empty)"
        }
    } catch {
        Write-Warning "Registry read failed: $_"
    }
}

# 1. Initial dump
Dump-State "INITIAL STATE"

# 2. Enable curve
Write-Host "`n[+] Enabling curve: $curveToTest" -ForegroundColor Yellow
try {
    Enable-TlsEccCurve -Name $curveToTest -Position 0
} catch {
    Write-Warning "Enable failed: $_"
}

# 3. Dump after enable
Dump-State "AFTER ENABLE"

# 4. Ensure registry explicitly contains it (defensive check)
Write-Host "`n[+] Verifying registry contains curve..."
$current = (Get-ItemProperty -Path $regPath -Name $regName).$regName
if ($current -notcontains $curveToTest) {
    Write-Warning "Curve not found in registry (may be overridden by GP or unsupported)"
}

# 5. Remove curve (clean rollback)
Write-Host "`n[+] Removing curve: $curveToTest" -ForegroundColor Yellow
try {
    Disable-TlsEccCurve -Name $curveToTest
} catch {
    Write-Warning "Disable failed: $_"
}

# 6. Final dump
Dump-State "AFTER REMOVE"

Write-Host "`n[+] Done." -ForegroundColor Green
