#Requires -Version 5.1
<#
.SYNOPSIS
    ssl-trust-unified.ps1 - Enterprise TLS/SSL trust distribution tool for Windows.

.DESCRIPTION
    Does the same job on Windows as its Linux counterpart 'ssl-trust-unified.sh':
    provides trusted access to applications with local/enterprise certificates
    (FreeIPA, Satellite/Foreman, Git, container registry, etc.) in a single step.

      1) Fetches the TLS certificate chain from target hosts via .NET SslStream
         (does NOT require openssl; works fully locally/offline).
      2) Builds a bundle from the CA (BasicConstraints CA=TRUE) certificates in the chain.
      3) Installs into the Windows certificate store:
           - Root CA         -> 'Root' (Trusted Root Certification Authorities)
           - Intermediate CA -> 'CA'   (Intermediate Certification Authorities)
           - Location        -> LocalMachine (admin) or CurrentUser (-UserMode, admin NOT required)
         This step COVERS Chrome, Edge, Internet Explorer and most .NET/CLI tools.
      4) Firefox: sets 'security.enterprise_roots.enabled=true' in each profile
         (so Firefox uses the Windows store) - no NSS certutil required.
      5) Java: imports into system/user JVM cacerts truststores via keytool.
      6) Docker Desktop: covered by the Windows Root store; for podman/WSL the
         generated ca.crt + clear instructions are provided.
      7) Generates PEM/CRT/DER/P7B + combined bundle + env-hints for CLI users.

.NOTES
    Version : 1.0  (matches Linux ssl-trust-unified.sh v2.0)
    Date    : 2026-07-07
    Compat  : Windows PowerShell 5.1 and PowerShell 7+
#>

[CmdletBinding()]
param(
    [string[]] $Target,
    [string]   $FromFile,
    [string[]] $Profiles,           # Not: $Profile PowerShell'de otomatik degiskendir; bu yuzden -Profiles
    [string]   $BaseDomain,
    [string[]] $Svc,
    [string]   $Out = ".\ssl-trust-out",

    [switch]   $UserMode,
    [switch]   $NoInstall,
    [switch]   $NoInstallSystem,
    [switch]   $NoFirefox,
    [switch]   $NoJava,
    [switch]   $NoContainers,
    [string]   $JavaStorePass = "changeit",

    [string[]] $AddLocalCa,
    [switch]   $AutoLocalCa,

    [int]      $TimeoutSec = 12,
    [switch]   $DryRun,
    [switch]   $Force,
    [switch]   $Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SCRIPT_VERSION = '1.0'
$RELEASE_DATE   = '2026-07-07'

if ($Version) { Write-Host "ssl-trust-unified.ps1 $SCRIPT_VERSION ($RELEASE_DATE)"; exit 0 }

# ============================ Loglama ============================
function Write-Log  { param([string]$m) Write-Host ("[{0}] {1}"        -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) }
function Write-Warn { param([string]$m) Write-Host ("[{0}] WARNING: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -ForegroundColor Yellow }
function Write-ErrL { param([string]$m) Write-Host ("[{0}] ERROR: {1}"  -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -ForegroundColor Red }
function Die        { param([string]$m) Write-ErrL $m; exit 1 }

# ============================ Durum ============================
$script:OkList     = New-Object System.Collections.ArrayList
$script:FailList   = New-Object System.Collections.ArrayList
$script:AllCa      = @{}   # thumbprint -> X509Certificate2 (birlesik bundle icin)

# Yonetici mi? (Windows disinda -orn. Linux'ta pwsh ile test- her zaman $false)
$IsAdmin = $false
if ($env:OS -eq 'Windows_NT') {
    $IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# ============================ Yardimcilar ============================
function Sanitize-Key { param([string]$s) return ($s -replace '[:\[\]]', '_') }

# Hedef ayristirma: https:// oneki, IPv6 [addr]:port, host[:port]
function Parse-Target {
    param([string]$raw)
    $t = $raw
    foreach ($p in @('https://','tls://','tcp://')) { if ($t.StartsWith($p)) { $t = $t.Substring($p.Length) } }
    $slash = $t.IndexOf('/'); if ($slash -ge 0) { $t = $t.Substring(0, $slash) }

    $hostName = ''; $port = 443
    if ($t.StartsWith('[')) {
        $end = $t.IndexOf(']')
        if ($end -lt 0) { throw "Invalid IPv6 target: $raw" }
        $hostName = $t.Substring(1, $end - 1)
        $rest = $t.Substring($end + 1)
        if ($rest.StartsWith(':')) { $port = [int]($rest.Substring(1)) }
    }
    elseif ($t.Contains(':')) {
        $idx = $t.LastIndexOf(':')
        $hostName = $t.Substring(0, $idx)
        $port = [int]($t.Substring($idx + 1))
    }
    else { $hostName = $t }

    if ([string]::IsNullOrWhiteSpace($hostName)) { throw "Invalid target (empty host): $raw" }
    if ($port -lt 1 -or $port -gt 65535)         { throw "Invalid port: $raw" }
    if ($hostName -notmatch '^[A-Za-z0-9._:\-]+$') { throw "Invalid host name: $raw" }
    return [pscustomobject]@{ Host = $hostName; Port = $port }
}

# PEM metnini X509 sertifika listesine cevir (coklu-sertifika destekli)
function Read-PemCerts {
    param([string]$path)
    $out = New-Object System.Collections.ArrayList
    $text = ''
    try { $text = Get-Content -Raw -LiteralPath $path } catch { $text = '' }
    if ($null -eq $text) { $text = '' }
    $rx = [regex]'(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
    foreach ($m in $rx.Matches($text)) {
        $b64 = ($m.Groups[1].Value -replace '\s', '')
        try {
            $bytes = [Convert]::FromBase64String($b64)
            [void]$out.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)))
        } catch { }
    }
    if ($out.Count -eq 0) {
        # DER olabilir
        try { [void]$out.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($path))) } catch { }
    }
    return ,$out
}

function ConvertTo-Pem {
    param($cert)
    $b64 = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----`r`n"
}

function Test-IsCA {
    param($cert)
    foreach ($ext in $cert.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            return [bool]$ext.CertificateAuthority
        }
    }
    return $false
}

function Get-CertSubject { param($c) try { return $c.Subject } catch { return '?' } }

function Write-BytesFile {
    param([string]$path, [byte[]]$bytes)
    [System.IO.File]::WriteAllBytes($path, $bytes)
}
function Write-TextFile {
    param([string]$path, [string]$text)
    $enc = New-Object System.Text.UTF8Encoding($false)  # BOM'suz UTF8 (PEM icin)
    [System.IO.File]::WriteAllText($path, $text, $enc)
}

# ---- TLS zincir cekme (yerel; openssl gerektirmez) ----
function Get-TlsChain {
    param([string]$hostName, [int]$port, [int]$timeoutSec)

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $tcp.BeginConnect($hostName, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($timeoutSec))) {
            throw "connection timed out ($timeoutSec sec)"
        }
        $tcp.EndConnect($iar)

        $captured = New-Object System.Collections.ArrayList
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sndr, $certificate, $chain, $errors)
            if ($chain -and $chain.ChainElements) {
                foreach ($el in $chain.ChainElements) {
                    [void]$captured.Add($el.Certificate.RawData)
                }
            }
            if ($captured.Count -eq 0 -and $certificate) {
                [void]$captured.Add($certificate.GetRawCertData())
            }
            return $true   # dogrulama degil, toplama modu
        }.GetNewClosure()

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        try {
            $protocols = [System.Security.Authentication.SslProtocols]::Tls12
            try { $protocols = $protocols -bor [System.Security.Authentication.SslProtocols]::Tls13 } catch { }
            # SNI: IP adreslerine host adi gonderme
            $sni = $hostName
            if ($hostName -match '^[0-9.]+$' -or $hostName.Contains(':')) { $sni = $hostName }
            $ssl.AuthenticateAsClient($sni, $null, $protocols, $false)
        }
        finally { $ssl.Dispose() }

        $certs = New-Object System.Collections.ArrayList
        foreach ($raw in $captured) {
            try { [void]$certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$raw))) } catch { }
        }
        return ,$certs
    }
    finally { $tcp.Close() }
}

# ---- Sertifika ozeti + suresi dolmus uyarisi ----
function Log-Cert {
    param($cert)
    $subj = Get-CertSubject $cert
    $end  = $cert.NotAfter
    Write-Log ("    certificate: {0} (expires: {1:yyyy-MM-dd})" -f $subj, $end)
    if ($cert.NotAfter -lt (Get-Date)) { Write-Warn "    EXPIRED certificate: $subj" }
}

function Collect-Ca { param($cert) if (-not $script:AllCa.ContainsKey($cert.Thumbprint)) { $script:AllCa[$cert.Thumbprint] = $cert } }

# ============================ Windows deposu ============================
function Add-ToWinStore {
    param($cert, [string]$storeName)   # 'Root' | 'CA'
    $loc = if ($UserMode) { 'CurrentUser' } else { 'LocalMachine' }
    $label = "$loc\$storeName"
    if ($DryRun) { Write-Log "    DRY-RUN> store import: $label <- $(Get-CertSubject $cert)"; return }
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $loc)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $exist = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $cert.Thumbprint, $false)
        if ($exist.Count -gt 0) {
            if ($Force) {
                foreach ($e in $exist) { $store.Remove($e) }
                $store.Add($cert)
                Write-Log "    refreshed (-Force) ($label): $(Get-CertSubject $cert)"
            } else {
                Write-Log "    already present, skipped ($label): $(Get-CertSubject $cert)"
            }
        } else {
            $store.Add($cert)
            Write-Log "    added ($label): $(Get-CertSubject $cert)"
        }
        $store.Close()
    } catch {
        Write-Warn "    store import failed ($label): $($_.Exception.Message)"
    }
}

function Install-WindowsTrust {
    param($caCerts, $leafFallback)
    if ($NoInstallSystem) { Write-Log "  Windows store installation disabled (-NoInstallSystem)."; return }
    if ($caCerts.Count -eq 0) {
        if ($leafFallback) {
            Write-Warn "  No CA:TRUE in chain; adding the leaf certificate to Root (warning)."
            Add-ToWinStore $leafFallback 'Root'
        }
        return
    }
    foreach ($c in $caCerts) {
        $selfSigned = ($c.Subject -eq $c.Issuer)
        if ($selfSigned) { Add-ToWinStore $c 'Root' } else { Add-ToWinStore $c 'CA' }
    }
}

# ============================ Firefox ============================
function Enable-FirefoxEnterpriseRoots {
    param([string]$homeDir)   # kullanici profil kok dizini (C:\Users\X)
    $base = Join-Path $homeDir 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (-not (Test-Path -LiteralPath $base)) { return $false }
    $any = $false
    foreach ($prof in (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
        $userjs = Join-Path $prof.FullName 'user.js'
        $line = 'user_pref("security.enterprise_roots.enabled", true);'
        $current = ''
        if (Test-Path -LiteralPath $userjs) { $current = Get-Content -Raw -LiteralPath $userjs }
        if ($current -match [regex]::Escape('security.enterprise_roots.enabled')) {
            Write-Log "    Firefox enterprise-roots already set: $($prof.Name)"
            $any = $true; continue
        }
        if ($DryRun) { Write-Log "    DRY-RUN> write Firefox user.js: $userjs"; $any = $true; continue }
        try {
            $nl = if ($current -and -not $current.EndsWith("`n")) { "`r`n" } else { '' }
            Add-Content -LiteralPath $userjs -Value ($nl + $line) -Encoding UTF8
            Write-Log "    Firefox enterprise-roots enabled: $($prof.Name)"
            $any = $true
        } catch { Write-Warn "    failed to write Firefox user.js ($($prof.Name)): $($_.Exception.Message)" }
    }
    return $any
}

function Install-Firefox {
    if ($NoFirefox) { return }
    Write-Log "  Configuring Firefox (enterprise-roots -> Windows store)"
    $homes = @()
    if ($UserMode) { $homes = @($env:USERPROFILE) }
    else {
        foreach ($d in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
            if ($d.Name -notin @('Public','Default','Default User','All Users')) { $homes += $d.FullName }
        }
    }
    $done = $false
    foreach ($h in $homes) { if (Enable-FirefoxEnterpriseRoots $h) { $done = $true } }
    if (-not $done) { Write-Log "    No Firefox profile found (it may not be installed)." }
}

# ============================ Java ============================
function Find-JavaCacerts {
    $roots = @(
        'C:\Program Files\Java',
        'C:\Program Files\Eclipse Adoptium',
        'C:\Program Files\Amazon Corretto',
        'C:\Program Files\Microsoft',
        'C:\Program Files\Zulu',
        'C:\Program Files\BellSoft',
        'C:\Program Files\RedHat',
        'C:\Program Files (x86)\Java'
    )
    if ($env:JAVA_HOME) { $roots += $env:JAVA_HOME }
    $found = New-Object System.Collections.ArrayList
    $seen  = @{}
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        try {
            Get-ChildItem -LiteralPath $r -Recurse -Filter 'cacerts' -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -match '\\lib\\security\\cacerts$' } |
              ForEach-Object {
                $rp = $_.FullName
                if (-not $seen.ContainsKey($rp)) { $seen[$rp] = $true; [void]$found.Add($rp) }
              }
        } catch { }
    }
    return ,$found
}

function Get-KeytoolFor {
    param([string]$cacertsPath)
    # cacerts: <home>\lib\security\cacerts  -> keytool: <home>\bin\keytool.exe
    $jhome = Split-Path (Split-Path (Split-Path $cacertsPath))
    $kt = Join-Path $jhome 'bin\keytool.exe'
    if (Test-Path -LiteralPath $kt) { return $kt }
    $g = Get-Command keytool -ErrorAction SilentlyContinue
    if ($g) { return $g.Source }
    return $null
}

function Install-Java {
    param($caCerts, [string]$nick)
    if ($NoJava) { return }
    $stores = Find-JavaCacerts
    if ($stores.Count -eq 0) { Write-Log "  No Java installation found; Java import skipped."; return }
    if ($caCerts.Count -eq 0) { return }

    foreach ($store in $stores) {
        $kt = Get-KeytoolFor $store
        if (-not $kt) { Write-Warn "    keytool not found; skipped: $store"; continue }
        $writable = $false
        try { $fs = [System.IO.File]::OpenWrite($store); $fs.Close(); $writable = $true } catch { $writable = $false }
        if (-not $writable -and $UserMode) { Write-Warn "    no write permission (-UserMode), skipped: $store"; continue }
        if (-not $writable -and -not $IsAdmin -and -not $DryRun) { Write-Warn "    no write permission (administrator required), skipped: $store"; continue }

        Write-Log "  Java truststore: $store"
        $i = 0
        foreach ($c in $caCerts) {
            $i++
            $alias = $nick; if ($caCerts.Count -gt 1) { $alias = "$nick-$i" }
            $alias = $alias.ToLower()
            $tmpCer = Join-Path $env:TEMP ("ssltrust-{0}-{1}.cer" -f $PID, $i)
            Write-TextFile $tmpCer (ConvertTo-Pem $c)
            try {
                if ($DryRun) {
                    Write-Log "    DRY-RUN> keytool import alias=$alias -> $store"
                } else {
                    # idempotent: ayni alias varsa sil
                    & $kt -list    -keystore $store -storepass $JavaStorePass -alias $alias *> $null
                    if ($LASTEXITCODE -eq 0) { & $kt -delete -keystore $store -storepass $JavaStorePass -alias $alias *> $null }
                    & $kt -importcert -noprompt -trustcacerts -alias $alias -file $tmpCer -keystore $store -storepass $JavaStorePass *> $null
                    if ($LASTEXITCODE -ne 0) { Write-Warn "    keytool import failed: $store ($alias) - is the storepass correct?" }
                    else { Write-Log "    imported: $alias" }
                }
            } finally { Remove-Item -LiteralPath $tmpCer -ErrorAction SilentlyContinue }
        }
    }
}

# ============================ Container (Docker/Podman) ============================
function Install-Containers {
    param([string]$caBundlePath, [string]$hostName, [int]$port)
    if ($NoContainers) { return }
    $key = $hostName; if ($port -ne 443) { $key = "${hostName}:${port}" }
    Write-Log "  Container trust: Docker Desktop uses the Windows Root store (covered above)."
    Write-Log "    ca.crt for podman/WSL: $caBundlePath"
    Write-Log ("    Example for installing into WSL: wsl -e sudo cp '<ca.crt>' /etc/pki/ca-trust/source/anchors/ ; wsl -e sudo update-ca-trust")
    # Ek olarak certs.d yapisini cikti altinda uretmek istenirse (referans):
    # <out>\certs.d\<key>\ca.crt  - ana islem process_target icinde yazilir.
}

# ============================ Yerel CA otomatik tespiti ============================
function Auto-LocalCa {
    $cands = @(
        (Join-Path $env:ProgramData 'ipa\ca.crt'),
        (Join-Path $env:ProgramData 'katello\ca.crt'),
        "$env:USERPROFILE\Downloads\ca.crt",
        "$env:USERPROFILE\Downloads\ca.pem"
    )
    foreach ($f in $cands) { if (Test-Path -LiteralPath $f) { $script:LocalCaFiles += $f } }
}

# ============================ Profil / servis ============================
function Default-PortForService { param([string]$s) if ($s -eq 'registry') { return 5000 } else { return 443 } }
function Normalize-Service {
    param([string]$s)
    switch ($s) {
        'ipa'     { return 'freeipa' }
        'katello' { return 'satellite' }
        'gitrepo' { return 'git' }
        default   { return $s }
    }
}
function Add-TargetSvc {
    param([string]$svc, [string]$hostport)
    if ([string]::IsNullOrWhiteSpace($hostport)) { return }
    $svc = Normalize-Service $svc
    if ($hostport.Contains(':')) { $script:TargetList += $hostport }
    else { $script:TargetList += ("{0}:{1}" -f $hostport, (Default-PortForService $svc)) }
}

function Expand-Profiles {
    foreach ($kv in $Svc) {
        if ($kv -notmatch '=') { Die "-Svc format: name=host[:port] (given: $kv)" }
        $name = $kv.Substring(0, $kv.IndexOf('='))
        $hp   = $kv.Substring($kv.IndexOf('=') + 1)
        Add-TargetSvc $name $hp
    }
    if ($Profiles -and $Profiles.Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace($BaseDomain)) { Die "-BaseDomain is required for -Profiles." }
        $plist = @()
        $hasAll = $false
        foreach ($p in $Profiles) { $pn = Normalize-Service $p; if ($pn -eq 'all') { $hasAll = $true } else { $plist += $pn } }
        if ($hasAll) { $plist = @('freeipa','satellite','foreman','git','registry') }
        foreach ($p in $plist) {
            switch ($p) {
                { $_ -in @('freeipa','satellite','foreman','git','registry') } { Add-TargetSvc $p "$p.$BaseDomain" }
                default { Write-Warn "Unknown profile skipped: $p" }
            }
        }
    }
}

# ============================ Cikti ============================
function Write-EnvHints {
    param([string]$bundle)
    $path = Join-Path $EffectiveOut 'env-hints.ps1'
    $content = @"
# Generated by ssl-trust-unified.ps1 $SCRIPT_VERSION - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Environment variable suggestions for CLI tools. To apply in this session:  . '$path'
# Use setx to make it permanent (takes effect in new sessions).

# EXTRA CA for Node.js (added on top of system CAs - safe):
`$env:NODE_EXTRA_CA_CERTS = '$bundle'
# setx NODE_EXTRA_CA_CERTS "$bundle"

# The following REPLACE the system CA store; enable only if really needed:
# `$env:GIT_SSL_CAINFO     = '$bundle'   # git
# `$env:CURL_CA_BUNDLE     = '$bundle'   # curl
# `$env:REQUESTS_CA_BUNDLE = '$bundle'   # python-requests
# `$env:SSL_CERT_FILE      = '$bundle'   # openssl-based tools
"@
    Write-TextFile $path $content
    Write-Log "Environment hints: $path"
}

function Finalize-Outputs {
    if ($script:AllCa.Count -eq 0) { return }
    $path = Join-Path $EffectiveOut 'all-ca-bundle.pem'
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $script:AllCa.Values) { [void]$sb.Append((ConvertTo-Pem $c)) }
    Write-TextFile $path $sb.ToString()
    Write-Log ("Combined CA bundle: {0} ({1} unique certificates)" -f $path, $script:AllCa.Count)
    if ($UserMode) { Write-EnvHints $path }
}

# ============================ Hedef isleme ============================
function Process-Target {
    param([string]$target)
    try {
        $pt = Parse-Target $target
    } catch {
        Write-ErrL $_.Exception.Message
        [void]$script:FailList.Add($target); return
    }
    $hostName = $pt.Host; $port = $pt.Port
    $key = $hostName; if ($port -ne 443) { $key = "${hostName}:${port}" }
    $tdir  = Join-Path $EffectiveOut (Sanitize-Key $key)
    $casdir = Join-Path $tdir 'cas'
    New-Item -ItemType Directory -Force -Path $tdir, $casdir | Out-Null

    Write-Log "Target: ${hostName}:${port}"
    Write-Log "  fetching certificate chain..."
    $chain = $null
    try { $chain = Get-TlsChain $hostName $port $TimeoutSec } catch {
        Write-Warn "  failed to fetch chain (${hostName}:${port}): $($_.Exception.Message) - skipped"
        [void]$script:FailList.Add($target); return
    }
    if (-not $chain -or $chain.Count -eq 0) {
        Write-Warn "  empty chain (${hostName}:${port}) - skipped"
        [void]$script:FailList.Add($target); return
    }

    # chain.pem + tekil sertifikalar + CA secimi
    $chainPem = New-Object System.Text.StringBuilder
    $caCerts  = New-Object System.Collections.ArrayList
    $leaf = $chain[0]
    $n = 0
    foreach ($c in $chain) {
        [void]$chainPem.Append((ConvertTo-Pem $c))
        Log-Cert $c
        if (Test-IsCA $c) {
            $n++
            [void]$caCerts.Add($c)
            Write-TextFile (Join-Path $casdir ("ca-{0:D2}.pem" -f $n)) (ConvertTo-Pem $c)
            Collect-Ca $c
        }
    }
    Write-TextFile (Join-Path $tdir 'chain.pem') $chainPem.ToString()

    if ($caCerts.Count -eq 0) {
        Write-Warn "  No CA:TRUE found in chain; the leaf certificate will be used."
        Write-TextFile (Join-Path $casdir 'ca-01.pem') (ConvertTo-Pem $leaf)
        Write-TextFile (Join-Path $tdir 'ca-bundle.pem') (ConvertTo-Pem $leaf)
        Collect-Ca $leaf
    } else {
        $bundleSb = New-Object System.Text.StringBuilder
        foreach ($c in $caCerts) { [void]$bundleSb.Append((ConvertTo-Pem $c)) }
        Write-TextFile (Join-Path $tdir 'ca-bundle.pem') $bundleSb.ToString()
    }

    # crt kopya + der (ilk CA/leaf) + p7b (tum zincir)
    $bundlePath = Join-Path $tdir 'ca-bundle.pem'
    Copy-Item -LiteralPath $bundlePath -Destination (Join-Path $tdir 'ca-bundle.crt') -Force
    $firstForDer = if ($caCerts.Count -gt 0) { $caCerts[0] } else { $leaf }
    Write-BytesFile (Join-Path $tdir 'ca-bundle.der') $firstForDer.RawData
    try {
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        foreach ($c in $chain) { [void]$col.Add($c) }
        Write-BytesFile (Join-Path $tdir 'chain.p7b') ($col.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7))
    } catch { }

    # certs.d referans yapisi (podman/WSL icin)
    if (-not $NoContainers) {
        $cdir = Join-Path (Join-Path $EffectiveOut 'certs.d') (Sanitize-Key $key)
        New-Item -ItemType Directory -Force -Path $cdir | Out-Null
        Copy-Item -LiteralPath $bundlePath -Destination (Join-Path $cdir 'ca.crt') -Force
    }

    $nick = "CA-$hostName-$port"

    Write-Log "  Windows certificate store"
    Install-WindowsTrust $caCerts $leaf
    if (-not $NoFirefox)    { Install-Firefox }
    if (-not $NoJava)       { Install-Java $caCerts $nick }
    if (-not $NoContainers) { Install-Containers (Join-Path $tdir 'ca-bundle.crt') $hostName $port }

    [void]$script:OkList.Add($target)
    Write-Log "  done: ${hostName}:${port}"
}

function Process-LocalCa {
    param([string]$f)
    if (-not (Test-Path -LiteralPath $f)) { Write-Warn "Local CA not found: $f"; [void]$script:FailList.Add($f); return }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($f)
    $name = "local_$base"
    $tdir  = Join-Path $EffectiveOut (Sanitize-Key $name)
    $casdir = Join-Path $tdir 'cas'
    New-Item -ItemType Directory -Force -Path $tdir, $casdir | Out-Null

    Write-Log "Local CA: $f"
    $certs = Read-PemCerts $f
    if ($certs.Count -eq 0) { Write-Warn "  no PEM/DER certificate found: $f - skipped"; [void]$script:FailList.Add($f); return }

    $bundleSb = New-Object System.Text.StringBuilder
    $caCerts = New-Object System.Collections.ArrayList
    $i = 0
    foreach ($c in $certs) {
        $i++
        Write-TextFile (Join-Path $casdir ("ca-{0:D2}.pem" -f $i)) (ConvertTo-Pem $c)
        [void]$bundleSb.Append((ConvertTo-Pem $c))
        [void]$caCerts.Add($c)
        Log-Cert $c
        Collect-Ca $c
    }
    Write-TextFile (Join-Path $tdir 'ca-bundle.pem') $bundleSb.ToString()
    Copy-Item -LiteralPath (Join-Path $tdir 'ca-bundle.pem') -Destination (Join-Path $tdir 'ca-bundle.crt') -Force
    Write-BytesFile (Join-Path $tdir 'ca-bundle.der') $certs[0].RawData

    Write-Log "  Windows certificate store"
    Install-WindowsTrust $caCerts $certs[0]
    if (-not $NoFirefox) { Install-Firefox }
    if (-not $NoJava)    { Install-Java $caCerts "CA-$name" }

    [void]$script:OkList.Add($f)
}

# ============================ Ana akis ============================
$script:TargetList  = @()
$script:LocalCaFiles = @()

if ($Target)     { $script:TargetList  += $Target }
if ($AddLocalCa) { $script:LocalCaFiles += $AddLocalCa }

if ($FromFile) {
    if (-not (Test-Path -LiteralPath $FromFile)) { Die "File not found: $FromFile" }
    foreach ($line in (Get-Content -LiteralPath $FromFile)) {
        $l = $line
        $h = $l.IndexOf('#'); if ($h -ge 0) { $l = $l.Substring(0, $h) }
        $l = $l.Trim()
        if ($l -eq '') { continue }
        $tok = ($l -split '\s+')[0]
        $script:TargetList += $tok
    }
}

# -NoInstall / -UserMode etkileri
if ($NoInstall) { $NoInstallSystem = $true; $NoFirefox = $true; $NoJava = $true; $NoContainers = $true }
if ($UserMode)  { $NoContainers = $true }   # container/registry sistem islemi; user-mode'da atla

if ($AutoLocalCa) { Auto-LocalCa }
Expand-Profiles

if ($script:TargetList.Count -eq 0 -and $script:LocalCaFiles.Count -eq 0) {
    Die "At least one -Target or -AddLocalCa/-AutoLocalCa is required. (Help: Get-Help .\ssl-trust-unified.ps1 -Full)"
}

# Yonetici gereksinimi (LocalMachine deposu / sistem Java)
$needsAdmin = (-not $UserMode) -and (-not $NoInstallSystem)
if ($needsAdmin -and -not $IsAdmin -and -not $DryRun) {
    Die "This operation writes to the LocalMachine store and requires ADMINISTRATOR rights. Solutions: (1) run PowerShell as administrator, or (2) use -UserMode (current user only, no administrator required)."
}

# Cikti dizini (dry-run'da gecici)
if ($DryRun) {
    $EffectiveOut = Join-Path ([System.IO.Path]::GetTempPath()) ("ssltrust-dry-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    Write-Log "DRY-RUN: no permanent changes will be made; files go to a temporary directory: $EffectiveOut"
} else {
    $EffectiveOut = $Out
}
New-Item -ItemType Directory -Force -Path $EffectiveOut | Out-Null

if ($UserMode) {
    Write-Log "*** USER MODE - administrator NOT required ***"
    Write-Log "    Certificates are added to the CurrentUser store; Chrome/Edge/IE use it. Firefox: enterprise-roots."
}

Write-Log "Version : $SCRIPT_VERSION ($RELEASE_DATE)"
Write-Log "OUT_DIR : $EffectiveOut"
$locLabel = if ($UserMode) { 'CurrentUser' } else { 'LocalMachine' }
Write-Log ("LOCATION: {0} | SYSTEM: {1} | FIREFOX: {2} | JAVA: {3} | CONTAINERS: {4} | USER_MODE: {5} | DRY: {6} | FORCE: {7} | ADMIN: {8}" -f `
    $locLabel, (-not $NoInstallSystem), (-not $NoFirefox), (-not $NoJava), (-not $NoContainers), [bool]$UserMode, [bool]$DryRun, [bool]$Force, $IsAdmin)

# Tekillestirme (sira korunur)
$script:TargetList   = $script:TargetList   | Select-Object -Unique
$script:LocalCaFiles = $script:LocalCaFiles | Select-Object -Unique

foreach ($t in $script:TargetList)   { Process-Target  $t }
foreach ($f in $script:LocalCaFiles) { Process-LocalCa $f }

Finalize-Outputs

Write-Log "----------------------------------------------------------------------"
Write-Log ("DONE. Succeeded: {0}  Failed: {1}  Output: {2}" -f $script:OkList.Count, $script:FailList.Count, $EffectiveOut)
if ($DryRun) { Write-Log "DRY-RUN: no permanent changes were made." }
if ($script:FailList.Count -gt 0) {
    Write-Warn ("Failed target(s): {0}" -f ($script:FailList -join ', '))
    exit 2
}
exit 0
