#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NoteBad++ - IOC Scanner for the Notepad++ supply chain attack (June-December 2025)

.DESCRIPTION
    This script checks for indicators of compromise (IoCs) associated with the
    Chrysalis backdoor deployed by Lotus Blossom APT via compromised Notepad++
    update infrastructure.

    Checks include:
    - Known malicious file hashes (SHA-1 from Kaspersky, SHA-256 from Rapid7)
    - Critical file paths (ProShow\load, Adobe\Scripts\alien.ini, Bluetooth\log.dll)
    - Registry/service/scheduled task persistence
    - DNS cache and hosts file for C2 domains
    - Network connections to C2 infrastructure
    - Event logs within the attack window

    This script is READ-ONLY and does NOT modify your system.

.PARAMETER ExportResults
    Export scan results to a text file (legacy format).

.PARAMETER ExportJson
    Export structured evidence as JSON for further analysis.

.PARAMETER OutputPath
    Custom path for the exported results file.

.PARAMETER DeepHashScan
    Extends hash scanning beyond AppData to Downloads, Temp, ProgramData.

.PARAMETER NoColor
    Disables colored output. Useful for piping or logging.

.PARAMETER AttackStart
    Start of attack window for log filtering. Default: 2025-06-01

.PARAMETER AttackEnd
    End of attack window for log filtering. Default: 2025-12-02

.EXAMPLE
    .\notebadpp.ps1
    Run a standard scan with colored output.

.EXAMPLE
    .\notebadpp.ps1 -DeepHashScan -ExportJson
    Run extended scan and export structured JSON evidence.

.EXAMPLE
    .\notebadpp.ps1 -AttackStart "2025-09-01" -AttackEnd "2025-11-15"
    Scan with custom attack window for log filtering.

.NOTES
    IoC Sources:
    - Kaspersky GReAT analysis (February 3, 2026)
    - Rapid7 Labs "The Chrysalis Backdoor" report (February 2026)

    Attack window: June 1, 2025 - December 2, 2025 (attacker access cutoff)

.LINK
    https://github.com/maremmano/notebadpp
#>

[CmdletBinding()]
param(
    [switch]$ExportResults,
    [switch]$ExportJson,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\NoteBadPP_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$DeepHashScan,
    [switch]$NoColor,
    [datetime]$AttackStart = '2025-06-01',
    [datetime]$AttackEnd = '2025-12-02'
)

# ============================================================================
# SCRIPT STATE & EVIDENCE COLLECTION
# ============================================================================

# Separate IOC findings (real compromise indicators) from Risk findings (config issues)
$script:IOCFindings = @()      # Hash matches, malicious files, C2 connections, etc.
$script:RiskFindings = @()     # Old version, GUP present, logging disabled, etc.
$script:Evidence = @()         # Structured evidence objects for JSON export
$script:Results = @()          # Legacy text output
$scanStartTime = Get-Date

function Add-Evidence {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description,
        [string]$Path = "",
        [string]$Hash = "",
        [datetime]$Timestamp = (Get-Date),
        [hashtable]$Extra = @{}
    )
    $evidence = [PSCustomObject]@{
        Category    = $Category
        Severity    = $Severity
        Description = $Description
        Path        = $Path
        Hash        = $Hash
        Timestamp   = $Timestamp
        ScanTime    = Get-Date
        Extra       = $Extra
    }
    $script:Evidence += $evidence
    return $evidence
}

function Write-IOC {
    param([string]$Message, [string]$Severity = "HIGH")
    $script:IOCFindings += $Message
    $output = "[IOC] [$Severity] $Message"
    if ($NoColor) {
        Write-Output $output
    } else {
        Write-Host $output -ForegroundColor Red
    }
    $script:Results += $output
}

function Write-Risk {
    param([string]$Message, [string]$Severity = "MEDIUM")
    $script:RiskFindings += $Message
    $output = "[RISK] [$Severity] $Message"
    if ($NoColor) {
        Write-Output $output
    } else {
        Write-Host $output -ForegroundColor Yellow
    }
    $script:Results += $output
}

function Write-Clean {
    param([string]$Message)
    $output = "[OK] $Message"
    if ($NoColor) {
        Write-Output $output
    } else {
        Write-Host $output -ForegroundColor Green
    }
    $script:Results += $output
}

function Write-Info {
    param([string]$Message)
    $output = "[*] $Message"
    if ($NoColor) {
        Write-Output $output
    } else {
        Write-Host $output -ForegroundColor Cyan
    }
    $script:Results += $output
}

function Write-Section {
    param([string]$Title)
    $separator = "=" * 70
    if ($NoColor) {
        Write-Output "`n$separator"
        Write-Output "  $Title"
        Write-Output "$separator"
    } else {
        Write-Host "`n$separator" -ForegroundColor Yellow
        Write-Host "  $Title" -ForegroundColor Yellow
        Write-Host "$separator" -ForegroundColor Yellow
    }
    $script:Results += "`n$separator`n  $Title`n$separator"
}

# Known malicious SHA1 hashes from the report
$MaliciousHashes = @(
    # Malicious updater.exe hashes
    "8e6e505438c21f3d281e1cc257abdbf7223b7f5a",
    "90e677d7ff5844407b9c073e3b7e896e078e11cd",
    "573549869e84544e3ef253bdba79851dcde4963a",
    "13179c8f19fbf3d8473c49983a199e6cb4f318f0",
    "4c9aac447bf732acc97992290aa7a187b967ee2c",
    "821c0cafb2aab0f063ef7e313f64313fc81d46cd",
    # Malicious auxiliary files
    "06a6a5a39193075734a32e0235bde0e979c27228",
    "9c3ba38890ed984a25abb6a094b5dbf052f22fa7",
    "ca4b6fe0c69472cd3d63b212eb805b7f65710d33",
    "0d0f315fd8cf408a483f8e2dd1e69422629ed9fd",
    "2a476cfb85fbf012fdbe63a37642c11afa5cf020",
    # Chain #1 files
    "defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c",
    "259cd3542dea998c57f67ffdd4543ab836e3d2a3",
    "46654a7ad6bc809b623c51938954de48e27a5618",
    "9df6ecc47b192260826c247bf8d40384aa6e6fd6",
    # Chain #2 files
    "6444dab57d93ce987c22da66b3706d5d7fc226da",
    "2ab0758dda4e71aee6f4c8e4c0265a796518f07d",
    "bf996a709835c0c16cce1015e6d44fc95e08a38a",
    # Chain #3 and Rapid7 identified files
    "d7ffd7b588880cf61b603346a3557e7cce648c93",
    "94dffa9de5b665dc51bc36e2693b8a3a0a4cc6b8",
    "21a942273c14e4b9d3faa58e4de1fd4d5014a1ed",
    "7e0790226ea461bcc9ecd4be3c315ace41e1c122",
    "f7910d943a013eede24ac89d6388c1b98f8b3717",
    "73d9d0139eaf89b7df34ceeb60e5f8c7cd2463bf",
    "bd4915b3597942d88f319740a9b803cc51585c4a",
    "c68d09dd50e357fd3de17a70b7724f8949441d77",
    "813ace987a61af909c053607635489ee984534f4",
    "9fbf2195dee991b1e5a727fd51391dcc2d7a4b16",
    "07d2a01e1dc94d59d5ca3bdf0c7848553ae91a51",
    "3090ecf034337857f786084fb14e63354e271c5d",
    "d0662eadbe5ba92acbd3485d8187112543bcfbf5",
    "9c0eff4deeb626730ad6a05c85eb138df48372ce"
)

# Malicious domains (including variants)
$MaliciousDomains = @(
    "cdncheck.it.com",
    "cdncheck.it",
    "self-dns.it.com",
    "self-dns.it",
    "safe-dns.it.com",
    "safe-dns.it",
    "api.wiresguard.com",
    "wiresguard.com",
    "api.skycloudcenter.com",
    "skycloudcenter.com",
    "temp.sh"
)

# Malicious IPs (Kaspersky + Rapid7)
$MaliciousIPs = @(
    "45.76.155.202",
    "45.77.31.210",
    "45.32.144.255",
    "95.179.213.0",
    "59.110.7.32",
    "124.222.137.114",
    "61.4.102.97"      # From Rapid7 report
)

# SHA-256 file indicators from Rapid7 Chrysalis report
# Source: https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
$Rapid7FileIndicators = @(
    @{ Name = "update.exe"; Hash = "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9"; Desc = "Malicious NSIS installer delivered via hijacked Notepad++ update" },
    @{ Name = "[NSIS.nsi]"; Hash = "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e"; Desc = "Installation script extracted from NSIS installer" },
    @{ Name = "BluetoothService.exe"; Hash = "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924"; Desc = "Renamed Bitdefender Submission Wizard used for DLL sideloading" },
    @{ Name = "BluetoothService"; Hash = "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e"; Desc = "Encrypted shellcode blob decrypted by log.dll (Chrysalis payload)" },
    @{ Name = "log.dll"; Hash = "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad"; Desc = "Malicious DLL sideloaded by BluetoothService.exe - decrypts Chrysalis" },
    @{ Name = "u.bat"; Hash = "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600"; Desc = "Batch script used for cleanup or persistence" },
    @{ Name = "conf.c"; Hash = "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a"; Desc = "Source with embedded Metasploit block_api shellcode, compiled via TCC" },
    @{ Name = "libtcc.dll"; Hash = "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906"; Desc = "Tiny C Compiler library used to compile conf.c at runtime" },
    @{ Name = "admin"; Hash = "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd"; Desc = "Cobalt Strike beacon payload downloaded from api.wiresguard.com" },
    @{ Name = "loader1"; Hash = "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd"; Desc = "Intermediate loader in shellcode execution chain" },
    @{ Name = "uffhxpSy"; Hash = "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8"; Desc = "Intermediate loader in shellcode execution chain" },
    @{ Name = "loader2"; Hash = "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda"; Desc = "Second-stage loader" },
    @{ Name = "3yzr31vk"; Hash = "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5"; Desc = "Second-stage loader" },
    @{ Name = "ConsoleApplication2.exe"; Hash = "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3"; Desc = "Warbird loader - abuses Microsoft Warbird framework" },
    @{ Name = "system"; Hash = "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd"; Desc = "Additional payload in attack toolchain" },
    @{ Name = "s047t5g.exe"; Hash = "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"; Desc = "Additional executable in attack toolchain" }
)
$Rapid7Hashes = $Rapid7FileIndicators | ForEach-Object { $_.Hash.ToLower() }

# ============================================================================
# HASHSETS FOR O(1) LOOKUPS
# ============================================================================
$SHA1HashSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]($MaliciousHashes | ForEach-Object { $_.ToLower() })
)
$SHA256HashSet = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]($Rapid7Hashes)
)
$MaliciousIPSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$MaliciousIPs)

# ============================================================================
# CRITICAL IOC PATHS (Kaspersky's strongest indicators)
# These are HIGH confidence IoCs - if present, likely compromised
# ============================================================================
$CriticalIOCPaths = @(
    "$env:APPDATA\ProShow\load",
    "$env:APPDATA\Adobe\Scripts\alien.ini",
    "$env:APPDATA\Adobe\Scripts\alien.dll",
    "$env:APPDATA\Bluetooth\BluetoothService.exe",
    "$env:APPDATA\Bluetooth\BluetoothService",
    "$env:APPDATA\Bluetooth\log.dll"
)

# Directories that MAY exist legitimately (downgrade to INFO unless files match)
$SuspiciousDirectories = @(
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Bluetooth"
)

# All suspicious file paths (for broader scanning)
$SuspiciousFiles = @(
    # ProShow chain
    "$env:APPDATA\ProShow\load",
    "$env:APPDATA\ProShow\ProShow.exe",
    "$env:APPDATA\ProShow\defscr",
    "$env:APPDATA\ProShow\if.dnt",
    "$env:APPDATA\ProShow\proshow.crs",
    "$env:APPDATA\ProShow\proshow.phd",
    "$env:APPDATA\ProShow\proshow_e.bmp",
    # Adobe\Scripts chain
    "$env:APPDATA\Adobe\Scripts\alien.dll",
    "$env:APPDATA\Adobe\Scripts\alien.ini",
    "$env:APPDATA\Adobe\Scripts\lua5.1.dll",
    "$env:APPDATA\Adobe\Scripts\script.exe",
    "$env:APPDATA\Adobe\Scripts\a.txt",
    # Bluetooth chain (Chrysalis)
    "$env:APPDATA\Bluetooth\BluetoothService.exe",
    "$env:APPDATA\Bluetooth\BluetoothService",
    "$env:APPDATA\Bluetooth\log.dll",
    "$env:APPDATA\Bluetooth\u.bat",
    "$env:APPDATA\Bluetooth\conf.c",
    "$env:APPDATA\Bluetooth\libtcc.dll"
)

# Specific IOC filenames to search for (used in targeted hash scanning)
$IOCFilenames = @(
    'update.exe', 'AutoUpdater.exe', 'install.exe',
    'BluetoothService.exe', 'BluetoothService', 'log.dll',
    'ConsoleApplication2.exe', 's047t5g.exe', 'libtcc.dll',
    'alien.dll', 'alien.ini', 'load', 'ProShow.exe'
)

# ============================================================================
# START CHECKS
# ============================================================================

Write-Host @"

ooooo      ooo               .             oooooooooo.        .o.       oooooooooo.
`888b.     `8'             .o8             `888'   `Y8b      .888.      `888'   `Y8b
 8 `88b.    8   .ooooo.  .o888oo  .ooooo.   888     888     .8"888.      888      888     88         88
 8   `88b.  8  d88' `88b   888   d88' `88b  888oooo888'    .8' `888.     888      888     88         88
 8     `88b.8  888   888   888   888ooo888  888    `88b   .88ooo8888.    888      888 8888888888 8888888888
 8       `888  888   888   888 . 888    .o  888    .88P  .8'     `888.   888     d88'     88         88
o8o        `8  `Y8bod8P'   "888" `Y8bod8P' o888bood8P'  o88o     o8888o o888bood8P'       88         88

    Notepad++ Supply Chain Attack IOC Scanner
    Based on Kaspersky GReAT + Rapid7 Labs Research (Feb 2026)

"@ -ForegroundColor Magenta

Write-Info "Starting scan at $(Get-Date)"
Write-Info "Running as: $env:USERNAME on $env:COMPUTERNAME"

# ============================================================================
# QUICK TRIAGE: Am I likely affected?
# ============================================================================
Write-Section "QUICK TRIAGE: Risk Assessment"

Write-Info "Checking if Notepad++ is installed and gathering basic info..."

$nppInstalled = $false
$nppVersion = $null
$gupFound = $false

$nppLocations = @(
    "$env:PROGRAMFILES\Notepad++",
    "${env:PROGRAMFILES(x86)}\Notepad++",
    "$env:LOCALAPPDATA\Programs\Notepad++"
)

foreach ($loc in $nppLocations) {
    $nppExe = Join-Path $loc "notepad++.exe"
    if (Test-Path $nppExe) {
        $nppInstalled = $true
        $nppVersion = (Get-Item $nppExe).VersionInfo.FileVersion
        $nppModified = (Get-Item $nppExe).LastWriteTime
        Write-Info "Notepad++ found: $loc"
        Write-Info "  Version: $nppVersion"
        Write-Info "  Last Modified: $nppModified"
        
        $gupPath = Join-Path $loc "updater\GUP.exe"
        if (Test-Path $gupPath) {
            $gupFound = $true
            $gupModified = (Get-Item $gupPath).LastWriteTime
            Write-Info "  GUP.exe (updater) present, modified: $gupModified"
        }
        break
    }
}

if (-not $nppInstalled) {
    Write-Clean "Notepad++ not found in standard locations - lower risk"
} else {
    Write-Host ""
    Write-Info "RISK ASSESSMENT FOR THIS ATTACK:"
    Write-Host ""
    Write-Info "  HIGHER RISK if:"
    Write-Info "    - Used auto-update (GUP.exe) between June-December 2025"
    Write-Info "    - In targeted profile: govt/financial org in VN, PH, SV, AU"
    Write-Info "    - Saw N++ spawning cmd.exe, curl.exe, or AutoUpdater.exe"
    Write-Host ""
    Write-Info "  LOWER RISK if:"
    Write-Info "    - Manual downloads from official notepad-plus-plus.org only"
    Write-Info "    - Updated after December 2025"
    Write-Info "    - Not in targeted sectors/regions"
    Write-Info "    - Using portable version (no updater)"
    Write-Host ""
    
    if ($gupFound) {
        Write-Risk "GUP.exe (auto-updater) is present - full scan recommended" "LOW"
        Write-Info "  The attack exploited the auto-update mechanism"
    } else {
        Write-Clean "GUP.exe not found - lower risk (manual updates only)"
    }

    # Check version for immediate risk assessment
    if ($nppVersion) {
        # Sanitize version string (sometimes contains text like "8.6.2 (64-bit)")
        $cleanVer = $nppVersion -replace '[^0-9\.]',''
        try {
            $vCurrent = [version]$cleanVer
            $vSafe = [version]"8.8.9"

            if ($vCurrent -lt $vSafe) {
                Write-Risk "Version $nppVersion is BELOW 8.8.9 - UPDATE RECOMMENDED" "MEDIUM"
            } else {
                Write-Clean "Version $nppVersion is patched (8.8.9+)"
            }
        } catch {
            Write-Info "  Could not parse version automatically. Please verify manually."
        }
    }
}

# ============================================================================
# CHECK 0: CRITICAL IOC PATHS (Highest confidence indicators)
# ============================================================================
Write-Section "CHECK 0: Critical IOC Paths (Highest Confidence)"

Write-Info "Checking for Kaspersky's strongest file-based indicators..."
$criticalFound = $false

foreach ($critPath in $CriticalIOCPaths) {
    if (Test-Path $critPath) {
        $fileInfo = Get-Item $critPath -Force
        Write-IOC "CRITICAL IOC FILE EXISTS: $critPath" "HIGH"
        Write-Info "  Size: $($fileInfo.Length) bytes"
        Write-Info "  Created: $($fileInfo.CreationTime)"
        Write-Info "  Modified: $($fileInfo.LastWriteTime)"

        Add-Evidence -Category "CriticalIOC" -Severity "HIGH" `
            -Description "Critical IOC file found" -Path $critPath `
            -Timestamp $fileInfo.LastWriteTime

        # Try to hash it
        try {
            $sha256 = (Get-FileHash $critPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            Write-Info "  SHA256: $sha256"
            if ($SHA256HashSet.Contains($sha256)) {
                Write-IOC "SHA256 MATCHES KNOWN MALICIOUS HASH" "HIGH"
            }
        } catch {}

        $criticalFound = $true
    }
}

if (-not $criticalFound) {
    Write-Clean "No critical IOC files found (good sign)"
}

# ============================================================================
# CHECK 1: Suspicious Directories (INFO only - directories can exist legitimately)
# ============================================================================
Write-Section "CHECK 1: Suspicious Directories"

Write-Info "Note: These directories CAN exist legitimately. Only escalate if malicious files found."

foreach ($dir in $SuspiciousDirectories) {
    if (Test-Path $dir) {
        Write-Info "Directory exists: $dir"
        $items = Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue
        if ($items) {
            Write-Info "  Contents ($($items.Count) items):"
            foreach ($item in $items) {
                $itemInfo = "    - $($item.Name)"
                if (-not $item.PSIsContainer) {
                    $itemInfo += " ($($item.Length) bytes)"
                }
                Write-Info $itemInfo
            }
        }
    } else {
        Write-Clean "Directory not found: $dir"
    }
}

# ============================================================================
# CHECK 2: Suspicious Files (IOCs if specific malicious files found)
# ============================================================================
Write-Section "CHECK 2: Suspicious Files"

$suspiciousFileFound = $false

foreach ($file in $SuspiciousFiles) {
    if (Test-Path $file) {
        $fileInfo = Get-Item $file -Force

        # Check if this is a critical IOC (already reported in CHECK 0)
        $isCritical = $CriticalIOCPaths -contains $file

        if (-not $isCritical) {
            Write-IOC "Suspicious file EXISTS: $file" "MEDIUM"
            Write-Info "  Size: $($fileInfo.Length) bytes"
            Write-Info "  Created: $($fileInfo.CreationTime)"
            Write-Info "  Modified: $($fileInfo.LastWriteTime)"

            Add-Evidence -Category "SuspiciousFile" -Severity "MEDIUM" `
                -Description "Suspicious file found" -Path $file `
                -Timestamp $fileInfo.LastWriteTime
        }
        $suspiciousFileFound = $true
    }
}

if (-not $suspiciousFileFound) {
    Write-Clean "No suspicious files found in expected IOC paths"
}

# Check for NSIS temp directories within attack window
$nsisTempDirs = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp" -Directory -Filter "ns*.tmp" -ErrorAction SilentlyContinue
if ($nsisTempDirs) {
    $attackWindowNsis = $nsisTempDirs | Where-Object {
        $_.CreationTime -ge $AttackStart -and $_.CreationTime -le $AttackEnd
    }

    if ($attackWindowNsis) {
        Write-IOC "NSIS temp directories from ATTACK WINDOW found:" "MEDIUM"
        foreach ($nsisDir in $attackWindowNsis) {
            Write-Info "  - $($nsisDir.FullName) (Created: $($nsisDir.CreationTime))"
        }
    } else {
        Write-Info "NSIS temp directories exist but outside attack window (likely benign)"
    }
} else {
    Write-Clean "No NSIS temp directories found"
}

# ============================================================================
# CHECK 3: Targeted Hash Verification (SHA-1 + SHA-256)
# ============================================================================
Write-Section "CHECK 3: Targeted Hash Verification"

Write-Info "Scanning specific IOC locations and filenames only (not entire Temp folder)..."

$filesToHash = @()

# 1. All files in suspicious directories
foreach ($dir in $SuspiciousDirectories) {
    if (Test-Path $dir) {
        $filesToHash += Get-ChildItem -Path $dir -File -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# 2. Specific IOC filenames in key locations (avoid recursive search on huge dirs)
$searchLocations = @(
    "$env:APPDATA\Notepad++",
    "$env:LOCALAPPDATA\Notepad++",
    "$env:PROGRAMFILES\Notepad++",
    "${env:PROGRAMFILES(x86)}\Notepad++",
    "$env:USERPROFILE\Downloads"
)

foreach ($loc in $searchLocations) {
    if (Test-Path $loc) {
        foreach ($iocName in $IOCFilenames) {
            $found = Get-ChildItem -Path $loc -Filter $iocName -File -Force -Recurse -ErrorAction SilentlyContinue
            if ($found) { $filesToHash += $found }
        }
    }
}

# 3. USOShared - only check if files exist AND are in attack window AND unsigned
$usoPath = "C:\ProgramData\USOShared"
if (Test-Path $usoPath) {
    $usoExes = Get-ChildItem -Path $usoPath -Filter "*.exe" -File -Force -ErrorAction SilentlyContinue
    foreach ($exe in $usoExes) {
        # Only flag if in attack window
        if ($exe.CreationTime -ge $AttackStart -and $exe.CreationTime -le $AttackEnd) {
            $sig = Get-AuthenticodeSignature -FilePath $exe.FullName -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') {
                $filesToHash += $exe
                Write-Info "USOShared exe in attack window (unsigned): $($exe.Name)"
            }
        }
    }
}

# Deduplicate files
$filesToHash = $filesToHash | Sort-Object FullName -Unique

$sha1Matches = 0
$sha256Matches = 0

if ($filesToHash.Count -gt 0) {
    Write-Info "Checking $($filesToHash.Count) targeted files against known hashes..."

    foreach ($file in $filesToHash) {
        try {
            # Check SHA-1
            $sha1 = (Get-FileHash -Path $file.FullName -Algorithm SHA1 -ErrorAction Stop).Hash.ToLower()
            if ($SHA1HashSet.Contains($sha1)) {
                Write-IOC "SHA-1 HASH MATCH: $($file.FullName)" "HIGH"
                Write-Info "  SHA-1: $sha1"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "SHA-1 matches known malicious hash" -Path $file.FullName -Hash $sha1
                $sha1Matches++
            }

            # Check SHA-256
            $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
            if ($SHA256HashSet.Contains($sha256)) {
                $matchInfo = $Rapid7FileIndicators | Where-Object { $_.Hash.ToLower() -eq $sha256 }
                Write-IOC "SHA-256 HASH MATCH: $($file.FullName)" "HIGH"
                Write-Info "  SHA-256: $sha256"
                Write-Info "  Known As: $($matchInfo.Name) - $($matchInfo.Desc)"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "SHA-256 matches Rapid7 Chrysalis IOC: $($matchInfo.Name)" `
                    -Path $file.FullName -Hash $sha256
                $sha256Matches++
            }
        } catch {
            # Skip files we can't hash
        }
    }

    if ($sha1Matches -eq 0 -and $sha256Matches -eq 0) {
        Write-Clean "No known malicious hashes found ($($filesToHash.Count) files checked)"
    } else {
        Write-Info "Hash matches: $sha1Matches SHA-1, $sha256Matches SHA-256"
    }
} else {
    Write-Clean "No targeted files to hash (suspicious directories don't exist)"
}

# Deep scan option for broader coverage
if ($DeepHashScan) {
    Write-Section "CHECK 3b: Extended Hash Scan (Deep Mode)"
    Write-Info "Deep scan: checking additional locations..."

    $deepPaths = @($env:TEMP, "$env:USERPROFILE\Downloads", "$env:ProgramData")
    $deepFilesScanned = 0
    $deepMatches = 0

    foreach ($deepPath in $deepPaths) {
        if (-not (Test-Path $deepPath)) { continue }
        # Only scan IOC filenames, not all exes
        foreach ($iocName in $IOCFilenames) {
            $found = Get-ChildItem -Path $deepPath -Filter $iocName -File -Force -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $found) {
                $deepFilesScanned++
                try {
                    $sha256 = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
                    if ($SHA256HashSet.Contains($sha256)) {
                        $matchInfo = $Rapid7FileIndicators | Where-Object { $_.Hash.ToLower() -eq $sha256 }
                        Write-IOC "DEEP SCAN SHA-256 MATCH: $($file.FullName)" "HIGH"
                        Write-Info "  Known As: $($matchInfo.Name)"
                        $deepMatches++
                    }
                } catch {}
            }
        }
    }

    if ($deepMatches -eq 0) {
        Write-Clean "Deep scan: no additional matches ($deepFilesScanned files checked)"
    }
}

# ============================================================================
# CHECK 4: Registry Autorun Entries
# ============================================================================
Write-Section "CHECK 4: Registry Autorun Entries"

$autorunPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$autorunFound = $false

foreach ($regPath in $autorunPaths) {
    if (Test-Path $regPath) {
        $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            # Cast to string to handle non-string registry values
            $value = [string]$_.Value
            if ([string]::IsNullOrEmpty($value)) { return }

            # Check for specific IOC patterns using -match (regex)
            if ($value -match '(?i)\\appdata\\roaming\\(ProShow|Adobe\\Scripts|Bluetooth)\\') {
                Write-IOC "Autorun points to IOC directory: $($_.Name)" "HIGH"
                Write-Info "  Path: $regPath"
                Write-Info "  Value: $value"
                Add-Evidence -Category "Persistence" -Severity "HIGH" `
                    -Description "Registry autorun points to IOC directory" -Path $regPath `
                    -Extra @{ Name = $_.Name; Value = $value }
                $autorunFound = $true
            }
            # Check for temp folder executables (suspicious pattern)
            elseif ($value -match '(?i)\\temp\\.*(update|autoupdater|install)\.exe') {
                Write-IOC "Autorun points to suspicious temp executable" "MEDIUM"
                Write-Info "  Path: $regPath"
                Write-Info "  Name: $($_.Name)"
                Write-Info "  Value: $value"
                $autorunFound = $true
            }
        }
    }
}

if (-not $autorunFound) {
    Write-Clean "No suspicious autorun entries found"
}

# ============================================================================
# CHECK 4b: Malicious Services
# ============================================================================
Write-Section "CHECK 4b: Malicious Services"

Write-Info "Checking for suspicious Windows services..."
$suspiciousServiceFound = $false

try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        $pathName = [string]$svc.PathName
        $svcName = $svc.Name

        if ([string]::IsNullOrEmpty($pathName)) { continue }

        # BluetoothService running from AppData is a strong IOC
        # (Legitimate Windows Bluetooth services run as svchost, not standalone exe)
        if ($pathName -match '(?i)\\appdata\\.*bluetooth') {
            Write-IOC "BluetoothService running from AppData (Chrysalis IOC)" "HIGH"
            Write-Info "  Service: $svcName"
            Write-Info "  Path: $pathName"
            Write-Info "  State: $($svc.State)"
            Add-Evidence -Category "Persistence" -Severity "HIGH" `
                -Description "Malicious BluetoothService" -Path $pathName
            $suspiciousServiceFound = $true
        }
        # Check for other suspicious paths
        elseif ($pathName -match '(?i)\\appdata\\roaming\\(ProShow|Adobe\\Scripts)\\') {
            Write-IOC "Service running from IOC directory" "HIGH"
            Write-Info "  Service: $svcName"
            Write-Info "  Path: $pathName"
            $suspiciousServiceFound = $true
        }
        # Any service in Temp folder is suspicious
        elseif ($pathName -match '(?i)\\temp\\' -and $pathName -notmatch 'Windows\\Temp') {
            Write-IOC "Service running from user Temp folder" "MEDIUM"
            Write-Info "  Service: $svcName"
            Write-Info "  Path: $pathName"
            $suspiciousServiceFound = $true
        }
    }

    if (-not $suspiciousServiceFound) {
        Write-Clean "No suspicious services found"
    }
} catch {
    Write-Info "Could not enumerate services"
}

# ============================================================================
# CHECK 4c: Scheduled Tasks
# ============================================================================
Write-Section "CHECK 4c: Scheduled Tasks"

Write-Info "Checking for suspicious scheduled tasks..."
$suspiciousTaskFound = $false

try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
    foreach ($task in $tasks) {
        foreach ($action in $task.Actions) {
            $execPath = [string]$action.Execute
            if ([string]::IsNullOrEmpty($execPath)) { continue }

            if ($execPath -match '(?i)\\appdata\\roaming\\(ProShow|Adobe\\Scripts|Bluetooth)\\') {
                Write-IOC "Scheduled task runs from IOC directory: $($task.TaskName)" "HIGH"
                Write-Info "  Path: $($task.TaskPath)"
                Write-Info "  Action: $execPath"
                Write-Info "  Arguments: $($action.Arguments)"
                Add-Evidence -Category "Persistence" -Severity "HIGH" `
                    -Description "Scheduled task persistence" -Path $execPath
                $suspiciousTaskFound = $true
            }
            elseif ($execPath -match '(?i)\\temp\\' -and $execPath -notmatch 'Windows\\Temp') {
                Write-IOC "Scheduled task runs from user Temp" "MEDIUM"
                Write-Info "  Task: $($task.TaskName)"
                Write-Info "  Action: $execPath"
                $suspiciousTaskFound = $true
            }
        }
    }

    if (-not $suspiciousTaskFound) {
        Write-Clean "No suspicious scheduled tasks found"
    }
} catch {
    Write-Info "Could not enumerate scheduled tasks"
}

# ============================================================================
# CHECK 5: DNS Cache
# ============================================================================
Write-Section "CHECK 5: DNS Cache Analysis"

try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    $maliciousDnsFound = $false
    
    foreach ($entry in $dnsCache) {
        foreach ($domain in $MaliciousDomains) {
            if ($entry.Name -like "*$domain*") {
                Write-IOC "MALICIOUS DOMAIN IN DNS CACHE: $($entry.Name)"
                Write-Info "  Data: $($entry.Data)"
                Write-Info "  TTL: $($entry.TimeToLive)"
                Add-Evidence -Category "Network" -Severity "HIGH" `
                    -Description "Malicious domain in DNS cache" -Extra @{ Domain = $entry.Name; Data = $entry.Data }
                $maliciousDnsFound = $true
            }
        }
    }
    
    if (-not $maliciousDnsFound) {
        Write-Clean "No malicious domains found in DNS cache"
    }
} catch {
    Write-Info "Could not retrieve DNS cache (may require elevated privileges)"
}

# ============================================================================
# CHECK 5b: Hosts File Analysis
# ============================================================================
Write-Section "CHECK 5b: Hosts File for C2 Domains"

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$C2Regex = ($MaliciousDomains | ForEach-Object { [regex]::Escape($_) }) -join '|'

if (Test-Path $hostsPath) {
    $hostsHit = Select-String -Path $hostsPath -Pattern $C2Regex -ErrorAction SilentlyContinue
    if ($hostsHit) {
        foreach ($hit in $hostsHit) {
            Write-IOC "MALICIOUS DOMAIN IN HOSTS FILE: $($hit.Line)"
            Write-Info "  Line number: $($hit.LineNumber)"
            Add-Evidence -Category "Network" -Severity "HIGH" `
                -Description "Malicious domain in hosts file" -Path $hostsPath -Extra @{ Line = $hit.Line; LineNumber = $hit.LineNumber }
        }
    } else {
        Write-Clean "No C2 domains found in hosts file"
    }
} else {
    Write-Info "Hosts file not found at expected location"
}

# ============================================================================
# CHECK 6: Active Network Connections
# ============================================================================
Write-Section "CHECK 6: Active Network Connections (TCP)"

try {
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq 'Established' -or $_.State -eq 'SynSent' }
    
    $maliciousConnFound = $false
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        if ($MaliciousIPs -contains $remoteIP) {
            Write-IOC "ACTIVE CONNECTION TO MALICIOUS IP: $remoteIP"
            Write-Info "  Local Port: $($conn.LocalPort)"
            Write-Info "  Remote Port: $($conn.RemotePort)"
            Write-Info "  State: $($conn.State)"
            $procName = "Unknown"
            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $procName = $process.Name
                Write-Info "  Process: $procName (PID: $($conn.OwningProcess))"
            } catch {}
            Add-Evidence -Category "Network" -Severity "HIGH" `
                -Description "Active connection to malicious IP" -Extra @{
                    RemoteIP = $remoteIP; LocalPort = $conn.LocalPort;
                    RemotePort = $conn.RemotePort; Process = $procName; PID = $conn.OwningProcess
                }
            $maliciousConnFound = $true
        }
    }
    
    if (-not $maliciousConnFound) {
        Write-Clean "No active connections to known malicious IPs"
    }
} catch {
    Write-Info "Could not check network connections"
}

# ============================================================================
# CHECK 6b: Netstat Scan (All Protocols)
# ============================================================================
Write-Section "CHECK 6b: Netstat Scan for C2 IPs (All Protocols)"

$ipPattern = ($MaliciousIPs | ForEach-Object { [regex]::Escape($_) }) -join '|'
try {
    $netstatOutput = netstat -an 2>$null | Select-String $ipPattern
    if ($netstatOutput) {
        foreach ($line in $netstatOutput) {
            Write-IOC "MALICIOUS IP IN NETSTAT: $line"
            Add-Evidence -Category "Network" -Severity "HIGH" `
                -Description "Malicious IP found in netstat output" -Extra @{ Entry = $line.ToString().Trim() }
        }
    } else {
        Write-Clean "No connections to C2 IPs found in netstat"
    }
} catch {
    Write-Info "Could not run netstat scan"
}

# ============================================================================
# CHECK 7: DNS Client Event Logs
# ============================================================================
Write-Section "CHECK 7: DNS Client Event Logs"

try {
    # Check if DNS Client logging is enabled and query logs
    $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    if ($dnsEvents) {
        $maliciousDnsLogs = $false
        foreach ($event in $dnsEvents) {
            $message = $event.Message
            foreach ($domain in $MaliciousDomains) {
                if ($message -like "*$domain*") {
                    Write-IOC "MALICIOUS DOMAIN IN DNS LOGS: $domain"
                    Write-Info "  Time: $($event.TimeCreated)"
                    Write-Info "  Event ID: $($event.Id)"
                    Add-Evidence -Category "Network" -Severity "HIGH" `
                        -Description "Malicious domain in DNS event logs" -Timestamp $event.TimeCreated `
                        -Extra @{ Domain = $domain; EventID = $event.Id }
                    $maliciousDnsLogs = $true
                }
            }
        }
        
        if (-not $maliciousDnsLogs) {
            Write-Clean "No malicious domains found in DNS event logs"
        }
    } else {
        Write-Info "DNS Client operational log is empty or not enabled"
        Write-Info "  To enable: wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true"
    }
} catch {
    Write-Info "Could not access DNS Client event logs (may not be enabled)"
}

# ============================================================================
# CHECK 8: Windows Firewall Logs (if available)
# ============================================================================
Write-Section "CHECK 8: Firewall Log Analysis"

$firewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

if (Test-Path $firewallLogPath) {
    Write-Info "Checking Windows Firewall log for malicious IPs..."
    try {
        $logContent = Get-Content $firewallLogPath -Tail 5000 -ErrorAction SilentlyContinue
        $maliciousFirewallHits = $false
        
        foreach ($line in $logContent) {
            foreach ($ip in $MaliciousIPs) {
                $escapedIP = [regex]::Escape($ip)
                if ($line -match $escapedIP) {
                    Write-IOC "MALICIOUS IP IN FIREWALL LOG: $ip"
                    Write-Info "  Log entry: $line"
                    Add-Evidence -Category "Network" -Severity "HIGH" `
                        -Description "Malicious IP in firewall log" -Path $firewallLogPath `
                        -Extra @{ IP = $ip; LogEntry = $line.Trim() }
                    $maliciousFirewallHits = $true
                }
            }
        }
        
        if (-not $maliciousFirewallHits) {
            Write-Clean "No malicious IPs found in firewall logs"
        }
    } catch {
        Write-Info "Could not read firewall log"
    }
} else {
    Write-Info "Windows Firewall logging not enabled or log not found"
    Write-Info "  Path checked: $firewallLogPath"
}

# ============================================================================
# CHECK 9: Sysmon DNS Query Logs (if Sysmon is installed)
# ============================================================================
Write-Section "CHECK 9: Sysmon DNS Query Logs"

try {
    $sysmonDnsEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=22]]" -MaxEvents 2000 -ErrorAction SilentlyContinue
    
    if ($sysmonDnsEvents) {
        $maliciousSysmonDns = $false
        foreach ($event in $sysmonDnsEvents) {
            $xml = [xml]$event.ToXml()
            $queryName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'QueryName' }).'#text'
            
            foreach ($domain in $MaliciousDomains) {
                if ($queryName -like "*$domain*") {
                    Write-IOC "MALICIOUS DNS QUERY IN SYSMON: $queryName"
                    Write-Info "  Time: $($event.TimeCreated)"
                    $processId = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'
                    $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                    Write-Info "  Process: $image (PID: $processId)"
                    Add-Evidence -Category "Network" -Severity "HIGH" `
                        -Description "Malicious DNS query in Sysmon" -Timestamp $event.TimeCreated `
                        -Extra @{ Query = $queryName; Process = $image; PID = $processId }
                    $maliciousSysmonDns = $true
                }
            }
        }
        
        if (-not $maliciousSysmonDns) {
            Write-Clean "No malicious DNS queries found in Sysmon logs"
        }
    } else {
        Write-Info "Sysmon not installed or no DNS query events found"
    }
} catch {
    Write-Info "Could not access Sysmon logs (Sysmon may not be installed)"
}

# ============================================================================
# CHECK 10: Running Process Analysis
# ============================================================================
Write-Section "CHECK 10: Running Process Analysis"

# Specific IOC process names (path-based verification required)
$iocProcessNames = @("BluetoothService", "ProShow", "ConsoleApplication2", "s047t5g")

# IOC directories - any process running from these is suspicious
$iocDirectories = @(
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Bluetooth"
)

$processes = Get-Process -ErrorAction SilentlyContinue
$suspiciousProcessFound = $false

foreach ($proc in $processes) {
    try {
        $procPath = $proc.MainModule.FileName
        if ([string]::IsNullOrEmpty($procPath)) { continue }

        # Check if process runs from IOC directories
        foreach ($iocDir in $iocDirectories) {
            if ($procPath -like "$iocDir*") {
                Write-IOC "Process running from IOC directory: $($proc.Name)" "HIGH"
                Write-Info "  PID: $($proc.Id)"
                Write-Info "  Path: $procPath"
                Write-Info "  Start Time: $($proc.StartTime)"

                # Check signature
                $sig = Get-AuthenticodeSignature -FilePath $procPath -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    Write-Info "  Signature: INVALID or UNSIGNED"
                } else {
                    Write-Info "  Signature: $($sig.SignerCertificate.Subject)"
                }

                Add-Evidence -Category "RunningProcess" -Severity "HIGH" `
                    -Description "Process running from IOC directory" -Path $procPath `
                    -Extra @{ PID = $proc.Id; StartTime = $proc.StartTime }
                $suspiciousProcessFound = $true
            }
        }

        # BluetoothService.exe - ANY instance outside of svchost is suspicious
        # (Windows Bluetooth runs via svchost, not standalone exe)
        if ($proc.Name -eq "BluetoothService") {
            Write-IOC "BluetoothService.exe running (Chrysalis IOC)" "HIGH"
            Write-Info "  PID: $($proc.Id)"
            Write-Info "  Path: $procPath"
            Write-Info "  Note: Legitimate Windows Bluetooth runs as svchost, not standalone exe"

            Add-Evidence -Category "RunningProcess" -Severity "HIGH" `
                -Description "BluetoothService.exe running - Chrysalis indicator" -Path $procPath
            $suspiciousProcessFound = $true
        }

        # Other specific IOC process names
        foreach ($iocName in $iocProcessNames) {
            if ($proc.Name -eq $iocName -and $iocName -ne "BluetoothService") {
                Write-IOC "IOC process name detected: $($proc.Name)" "MEDIUM"
                Write-Info "  PID: $($proc.Id)"
                Write-Info "  Path: $procPath"
                $suspiciousProcessFound = $true
            }
        }

    } catch {
        # Can't access process info (likely system process)
    }
}

# Check for GUP.exe (informational only, not an IOC)
$gupProcesses = Get-Process -Name "GUP" -ErrorAction SilentlyContinue
if ($gupProcesses) {
    Write-Info "GUP.exe (Notepad++ updater) is currently running"
    foreach ($gup in $gupProcesses) {
        Write-Info "  PID: $($gup.Id)"
        try {
            Write-Info "  Path: $($gup.MainModule.FileName)"
        } catch {}
    }
}

if (-not $suspiciousProcessFound) {
    Write-Clean "No suspicious processes currently running"
}

# ============================================================================
# CHECK 11: Command History Analysis (PowerShell + CMD)
# ============================================================================
Write-Section "CHECK 11: Command History Analysis"

# Specific malicious command patterns from the attack
$maliciousCommandPatterns = @(
    "whoami&&tasklist",
    "whoami&&tasklist&&systeminfo&&netstat",
    'curl.exe -F "file=@.*" .*temp\.sh',
    "curl.*temp\.sh/upload",
    "whoami >> a.txt",
    "tasklist >> a.txt",
    "systeminfo >> a.txt",
    "netstat -ano >> a.txt",
    "whoami.*tasklist.*>.*\.txt"
)

# Check PowerShell history
$psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

if (Test-Path $psHistoryPath) {
    Write-Info "Checking PowerShell history: $psHistoryPath"
    $history = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
    
    $maliciousHistoryFound = $false
    $lineNum = 0
    foreach ($line in $history) {
        $lineNum++
        foreach ($pattern in $maliciousCommandPatterns) {
            if ($line -match $pattern) {
                Write-IOC "MALICIOUS COMMAND PATTERN IN POWERSHELL HISTORY"
                Write-Info "  Line $lineNum`: $line"
                Write-Info "  Pattern: $pattern"
                Add-Evidence -Category "CommandHistory" -Severity "HIGH" `
                    -Description "Malicious command pattern in PowerShell history" -Path $psHistoryPath `
                    -Extra @{ Command = $line.Trim(); Pattern = $pattern; Line = $lineNum }
                $maliciousHistoryFound = $true
            }
        }
        # Also check for temp.sh references
        if ($line -match "temp\.sh") {
            Write-IOC "Reference to temp.sh found in PowerShell history"
            Write-Info "  Line $lineNum`: $line"
            Add-Evidence -Category "CommandHistory" -Severity "HIGH" `
                -Description "Reference to temp.sh in PowerShell history" -Path $psHistoryPath `
                -Extra @{ Command = $line.Trim(); Line = $lineNum }
            $maliciousHistoryFound = $true
        }
    }
    
    if (-not $maliciousHistoryFound) {
        Write-Clean "No malicious command patterns in PowerShell history"
    }
} else {
    Write-Info "PowerShell history file not found at expected location"
}

# Check CMD history via registry (ConsoleHost stores recent commands)
try {
    $cmdHistory = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
    if ($cmdHistory) {
        Write-Info "Checking Run dialog history..."
        $cmdHistory.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object {
            $cmd = $_.Value
            foreach ($pattern in $maliciousCommandPatterns) {
                if ($cmd -match $pattern) {
                    Write-IOC "Malicious command in Run history: $cmd"
                    Add-Evidence -Category "CommandHistory" -Severity "HIGH" `
                        -Description "Malicious command in Run history" `
                        -Extra @{ Command = $cmd; Pattern = $pattern }
                }
            }
        }
    }
} catch {
    Write-Info "Could not check Run dialog history"
}

# Quick search for the exact reconnaissance command string
Write-Info "Searching for exact attack command signatures..."
$searchPaths = @(
    $psHistoryPath,
    "$env:APPDATA\ProShow\1.txt",
    "$env:APPDATA\Adobe\Scripts\a.txt"
)

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        $content = Get-Content $searchPath -Raw -ErrorAction SilentlyContinue
        if ($content -match "whoami|AUTHORITY\\") {
            Write-IOC "Reconnaissance output file found: $searchPath"
            Write-Info "  This file may contain exfiltrated system info"
            Add-Evidence -Category "ReconFile" -Severity "HIGH" `
                -Description "Reconnaissance output file found" -Path $searchPath
        }
    }
}

# ============================================================================
# CHECK 12: Notepad++ Security Log (v8.9+)
# ============================================================================
Write-Section "CHECK 12: Notepad++ Security Error Log"

$securityLogPath = "$env:LOCALAPPDATA\Notepad++\log\securityError.log"

if (Test-Path $securityLogPath) {
    # securityError.log existence alone is NOT an IOC - it just means signature checks failed
    # Only escalate if it contains entries from the attack window or mentions suspicious domains
    Write-Info "securityError.log exists (Notepad++ logged update verification failures)"
    Write-Info "  Path: $securityLogPath"

    $logContent = Get-Content $securityLogPath -ErrorAction SilentlyContinue
    $suspiciousEntries = @()

    foreach ($line in $logContent) {
        # Check for C2 domains or suspicious URLs in log
        if ($line -match 'cdncheck|self-dns|safe-dns|wiresguard|skycloudcenter|temp\.sh') {
            $suspiciousEntries += $line
        }
        # Check for entries during attack window (if dates are in the log)
        if ($line -match '202[5]-(0[6-9]|1[0-2])' -or $line -match '2025.*(Jun|Jul|Aug|Sep|Oct|Nov|Dec)') {
            $suspiciousEntries += $line
        }
    }

    if ($suspiciousEntries.Count -gt 0) {
        Write-IOC "Security log contains suspicious entries from attack window" "MEDIUM"
        foreach ($entry in ($suspiciousEntries | Select-Object -First 10)) {
            Write-Info "  $entry"
            Add-Evidence -Category "SecurityLog" -Severity "MEDIUM" `
                -Description "Suspicious entry in Notepad++ security log" -Path $securityLogPath `
                -Extra @{ Entry = $entry.Trim() }
        }
    } else {
        Write-Info "  Log exists but no suspicious entries found (likely benign verification failures)"
        Write-Info "  Last 5 lines:"
        $logContent | Select-Object -Last 5 | ForEach-Object { Write-Info "    $_" }
    }
} else {
    Write-Clean "No securityError.log found (normal for older N++ versions or no update failures)"
}

# ============================================================================
# CHECK 13: Downloads Folder Scan
# ============================================================================
Write-Section "CHECK 13: Downloads Folder Analysis"

$downloadsPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop"
)

$suspiciousDownloadNames = @(
    "update.exe",
    "install.exe",
    "AutoUpdater.exe",
    "GUP.exe"
)

foreach ($dlPath in $downloadsPaths) {
    if (Test-Path $dlPath) {
        foreach ($fileName in $suspiciousDownloadNames) {
            $files = Get-ChildItem -Path $dlPath -Filter $fileName -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Risk "Suspicious file in $dlPath`: $($file.Name)" "MEDIUM"
                Write-Info "  Full path: $($file.FullName)"
                Write-Info "  Created: $($file.CreationTime)"
                Write-Info "  Size: $($file.Length) bytes"
                try {
                    $sha1 = (Get-FileHash -Path $file.FullName -Algorithm SHA1).Hash.ToLower()
                    Write-Info "  SHA1: $sha1"
                    if ($SHA1HashSet.Contains($sha1)) {
                        Write-IOC "MALICIOUS HASH MATCH (SHA1): $($file.FullName)" "HIGH"
                        Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                            -Description "SHA1 matches known malicious hash" -Path $file.FullName -Hash $sha1
                    }

                    $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
                    Write-Info "  SHA256: $sha256"
                    if ($SHA256HashSet.Contains($sha256)) {
                        $matchInfo = $Rapid7FileIndicators | Where-Object { $_.Hash.ToLower() -eq $sha256 }
                        Write-IOC "MALICIOUS HASH MATCH (SHA256): $($file.FullName)" "HIGH"
                        Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                            -Description "SHA256 matches known malicious hash: $($matchInfo.Name)" -Path $file.FullName -Hash $sha256
                    }
                } catch {}
            }
        }
    }
}
Write-Clean "Downloads folder scan completed"

# ============================================================================
# CHECK 14: Temp Folder Deep Scan
# ============================================================================
Write-Section "CHECK 14: Temp Folder Analysis"

$tempPath = "$env:LOCALAPPDATA\Temp"

# Check for malicious executables in Temp
$tempSuspiciousFiles = @("update.exe", "install.exe", "AutoUpdater.exe")
foreach ($fileName in $tempSuspiciousFiles) {
    $tempFile = Join-Path $tempPath $fileName
    if (Test-Path $tempFile) {
        Write-Risk "SUSPICIOUS FILE IN TEMP: $tempFile"
        $fileInfo = Get-Item $tempFile
        Write-Info "  Created: $($fileInfo.CreationTime)"
        Write-Info "  Modified: $($fileInfo.LastWriteTime)"
        Write-Info "  Size: $($fileInfo.Length) bytes"
        try {
            $sha1 = (Get-FileHash -Path $tempFile -Algorithm SHA1).Hash.ToLower()
            Write-Info "  SHA1: $sha1"
            if ($SHA1HashSet.Contains($sha1)) {
                Write-IOC "CONFIRMED MALICIOUS (SHA1): $tempFile" "HIGH"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "SHA1 matches known malicious hash" -Path $tempFile -Hash $sha1
            }

            $sha256 = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
            Write-Info "  SHA256: $sha256"
            if ($SHA256HashSet.Contains($sha256)) {
                $matchInfo = $Rapid7FileIndicators | Where-Object { $_.Hash.ToLower() -eq $sha256 }
                Write-IOC "CONFIRMED MALICIOUS (SHA256): $tempFile" "HIGH"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "SHA256 matches known malicious hash: $($matchInfo.Name)" -Path $tempFile -Hash $sha256
            }
        } catch {}
    }
}

# Check for NSIS installer remnants with more detail
$nsisPattern = Join-Path $tempPath "ns*.tmp"
$nsisDirs = Get-ChildItem -Path $tempPath -Directory -Filter "ns*.tmp" -ErrorAction SilentlyContinue

if ($nsisDirs) {
    Write-Info "NSIS temp directories found (indicates recent NSIS installer execution):"
    foreach ($nsisDir in $nsisDirs) {
        Write-Info "  - $($nsisDir.FullName)"
        Write-Info "    Created: $($nsisDir.CreationTime)"
        
        # Check if created during attack window
        if ($nsisDir.CreationTime -ge $AttackStart -and $nsisDir.CreationTime -le $AttackEnd) {
            Write-Risk "NSIS directory created during attack window" "MEDIUM"
            Add-Evidence -Category "Staging" -Severity "MEDIUM" `
                -Description "NSIS temp directory created during attack window" -Path $nsisDir.FullName `
                -Timestamp $nsisDir.CreationTime
        }
    }
} else {
    Write-Clean "No NSIS temp directories found"
}

# ============================================================================
# CHECK 15: Event Viewer - Suspicious Process Creation
# ============================================================================
Write-Section "CHECK 15: Event Viewer - Process Creation Analysis"

try {
    # Check Security log for process creation (Event ID 4688) if enabled
    Write-Info "Checking for suspicious process creation events..."
    
    $suspiciousProcessPatterns = @(
        "curl.exe.*temp\.sh",
        "whoami.*tasklist",
        "systeminfo.*netstat",
        "GUP\.exe.*update\.exe",
        "GUP\.exe.*AutoUpdater\.exe"
    )
    
    # Try to get process creation events from Security log
    $processEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 500 -ErrorAction SilentlyContinue
    
    if ($processEvents) {
        $suspiciousEventFound = $false
        foreach ($event in $processEvents) {
            $message = $event.Message
            foreach ($pattern in $suspiciousProcessPatterns) {
                if ($message -match $pattern) {
                    Write-Risk "Suspicious process creation detected"
                    Write-Info "  Time: $($event.TimeCreated)"
                    Write-Info "  Pattern matched: $pattern"
                    Add-Evidence -Category "EventLog" -Severity "MEDIUM" `
                        -Description "Suspicious process creation event" -Timestamp $event.TimeCreated `
                        -Extra @{ Pattern = $pattern; EventID = $event.Id }
                    $suspiciousEventFound = $true
                }
            }
        }
        if (-not $suspiciousEventFound) {
            Write-Clean "No suspicious process creation patterns in recent Security events"
        }
    } else {
        Write-Info "Process creation auditing may not be enabled (Event ID 4688)"
    }
} catch {
    Write-Info "Could not access Security event log (requires elevation or auditing enabled)"
}

# Check PowerShell operational log for suspicious activity
try {
    $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 500 -ErrorAction SilentlyContinue
    
    if ($psEvents) {
        $suspiciousPsFound = $false
        foreach ($event in $psEvents) {
            $message = $event.Message
            if ($message -match "temp\.sh|whoami.*tasklist|curl.*upload" -or
                $message -match "ProShow|alien\.ini|BluetoothService") {
                Write-Risk "Suspicious PowerShell activity detected"
                Write-Info "  Time: $($event.TimeCreated)"
                Write-Info "  Event ID: $($event.Id)"
                Add-Evidence -Category "EventLog" -Severity "MEDIUM" `
                    -Description "Suspicious PowerShell activity in operational log" -Timestamp $event.TimeCreated `
                    -Extra @{ EventID = $event.Id }
                $suspiciousPsFound = $true
            }
        }
        if (-not $suspiciousPsFound) {
            Write-Clean "No suspicious patterns in PowerShell operational log"
        }
    }
} catch {
    Write-Info "Could not access PowerShell operational log"
}

# ============================================================================
# CHECK 16: Notepad++ Installation Deep Analysis
# ============================================================================
Write-Section "CHECK 16: Notepad++ Installation Deep Analysis"

$nppPaths = @(
    "$env:PROGRAMFILES\Notepad++",
    "${env:PROGRAMFILES(x86)}\Notepad++",
    "$env:LOCALAPPDATA\Programs\Notepad++"
)

foreach ($nppPath in $nppPaths) {
    if (Test-Path $nppPath) {
        Write-Info "Notepad++ installation found: $nppPath"
        
        $nppExe = Join-Path $nppPath "notepad++.exe"
        if (Test-Path $nppExe) {
            $fileVerInfo = (Get-Item $nppExe).VersionInfo.FileVersion
            Write-Info "  Version: $fileVerInfo"
            Write-Info "  Modified: $((Get-Item $nppExe).LastWriteTime)"

            # Version check - recommend update if below 8.8.9
            # Sanitize version string (sometimes contains text like "8.6.2 (64-bit)")
            $cleanVer = $fileVerInfo -replace '[^0-9\.]',''

            try {
                $vCurrent = [version]$cleanVer
                $vSafe = [version]"8.8.9"
                $vSecure = [version]"8.9.0"

                if ($vCurrent -lt $vSafe) {
                    Write-Risk "Notepad++ version is below 8.8.9 - CRITICAL: UPDATE IMMEDIATELY" "HIGH"
                    Write-Info "  Version 8.8.9+ includes critical security fixes for this attack"
                    Write-Info "  Download from: https://notepad-plus-plus.org/downloads/"
                } elseif ($vCurrent -lt $vSecure) {
                    Write-Risk "Notepad++ version is below 8.9 - RECOMMEND UPDATE" "MEDIUM"
                    Write-Info "  Version 8.9+ includes enhanced signature verification"
                } else {
                    Write-Clean "Notepad++ version $cleanVer is current (8.9+)"
                }
            } catch {
                Write-Info "  Could not parse version automatically. Please verify manually."
            }
            
            # Calculate SHA256 hash for integrity verification
            $nppHash = (Get-FileHash -Path $nppExe -Algorithm SHA256).Hash
            Write-Info "  SHA256: $nppHash"
            Write-Info "  Verify this hash against official releases at:"
            Write-Info "  https://github.com/notepad-plus-plus/notepad-plus-plus/releases"
        }
        
        $gupExe = Join-Path $nppPath "updater\GUP.exe"
        if (Test-Path $gupExe) {
            Write-Info "  GUP.exe (updater) found: $gupExe"
            Write-Info "  GUP Modified: $((Get-Item $gupExe).LastWriteTime)"
            $gupSha256 = (Get-FileHash -Path $gupExe -Algorithm SHA256).Hash.ToLower()
            Write-Info "  GUP SHA256: $gupSha256"
            if ($SHA256HashSet.Contains($gupSha256)) {
                Write-IOC "MALICIOUS GUP.EXE DETECTED (SHA256): $gupExe" "HIGH"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "GUP.exe SHA256 matches known malicious hash" -Path $gupExe -Hash $gupSha256
            }
            $gupSha1 = (Get-FileHash -Path $gupExe -Algorithm SHA1).Hash.ToLower()
            Write-Info "  GUP SHA1: $gupSha1"
            if ($SHA1HashSet.Contains($gupSha1)) {
                Write-IOC "MALICIOUS GUP.EXE DETECTED (SHA1): $gupExe" "HIGH"
                Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                    -Description "GUP.exe SHA1 matches known malicious hash" -Path $gupExe -Hash $gupSha1
            }
        }
        
        # Check for any update.exe files
        $updateFiles = Get-ChildItem -Path $nppPath -Recurse -Filter "update*.exe" -ErrorAction SilentlyContinue
        foreach ($updateFile in $updateFiles) {
            Write-Info "  Update file found: $($updateFile.FullName)"

            try {
                $sha1 = (Get-FileHash -Path $updateFile.FullName -Algorithm SHA1).Hash.ToLower()
                Write-Info "    SHA1: $sha1"
                if ($SHA1HashSet.Contains($sha1)) {
                    Write-IOC "MALICIOUS UPDATE FILE DETECTED (SHA1): $($updateFile.FullName)" "HIGH"
                    Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                        -Description "Update file SHA1 matches known malicious hash" -Path $updateFile.FullName -Hash $sha1
                }

                $sha256 = (Get-FileHash -Path $updateFile.FullName -Algorithm SHA256).Hash.ToLower()
                Write-Info "    SHA256: $sha256"
                if ($SHA256HashSet.Contains($sha256)) {
                    $matchInfo = $Rapid7FileIndicators | Where-Object { $_.Hash.ToLower() -eq $sha256 }
                    Write-IOC "MALICIOUS UPDATE FILE DETECTED (SHA256): $($updateFile.FullName)" "HIGH"
                    Add-Evidence -Category "HashMatch" -Severity "HIGH" `
                        -Description "Update file SHA256 matches known malicious hash: $($matchInfo.Name)" -Path $updateFile.FullName -Hash $sha256
                }
            } catch {}
        }
        
        # Check change.log for update history
        $changeLog = Join-Path $nppPath "change.log"
        if (Test-Path $changeLog) {
            Write-Info "  change.log found - can review for update history"
        }
    }
}

# ============================================================================
# CHECK 17: Integrity Verification Against Known Good Hashes
# ============================================================================
Write-Section "CHECK 17: File Integrity Verification"

Write-Info "Generating hashes for key Notepad++ files for manual verification..."
Write-Info "Compare these against official GitHub release hashes"
Write-Info ""

foreach ($nppPath in $nppPaths) {
    if (Test-Path $nppPath) {
        $filesToHash = @(
            "notepad++.exe",
            "updater\GUP.exe",
            "SciLexer.dll",
            "plugins\Config\nppPluginList.dll"
        )
        
        Write-Info "Installation: $nppPath"
        Write-Info ("-" * 50)
        
        foreach ($file in $filesToHash) {
            $fullPath = Join-Path $nppPath $file
            if (Test-Path $fullPath) {
                try {
                    $sha256 = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash
                    $fileSize = (Get-Item $fullPath).Length
                    Write-Info "  $file"
                    Write-Info "    Size: $fileSize bytes"
                    Write-Info "    SHA256: $sha256"
                } catch {
                    Write-Info "  $file - Could not hash"
                }
            }
        }
        
        Write-Info ""
        Write-Info "To verify integrity:"
        Write-Info "  1. Go to: https://github.com/notepad-plus-plus/notepad-plus-plus/releases"
        Write-Info "  2. Find your version and download the SHA-256 checksums file"
        Write-Info "  3. Compare the hashes above with the official checksums"
        break
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Section "SCAN SUMMARY"

$iocCount = $script:IOCFindings.Count
$riskCount = $script:RiskFindings.Count
$evidenceCount = $script:Evidence.Count

$summary = @"
Scan completed at: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Scan Duration: $([math]::Round(((Get-Date) - $scanStartTime).TotalSeconds, 2)) seconds
Attack Window: $($AttackStart.ToString('yyyy-MM-dd')) to $($AttackEnd.ToString('yyyy-MM-dd'))

Results:
  IOC Findings (compromise indicators): $iocCount
  Risk Findings (config/hygiene issues): $riskCount
  Evidence items collected: $evidenceCount
"@

if ($NoColor) {
    Write-Output $summary
} else {
    Write-Host $summary
}
$script:Results += $summary

# Only show COMPROMISE banner if actual IOCs were found (not just risks)
if ($iocCount -gt 0) {
    if ($NoColor) {
        Write-Output "`n$("=" * 70)"
        Write-Output "[!!!] INDICATORS OF COMPROMISE DETECTED!"
        Write-Output ("=" * 70)
        Write-Output "`nIOC FINDINGS ($iocCount):"
        foreach ($ioc in $script:IOCFindings) { Write-Output "  - $ioc" }
        Write-Output "`nIMMEDIATE ACTIONS:"
        Write-Output "  1. DISCONNECT from network NOW (Wi-Fi off / unplug Ethernet)"
        Write-Output "  2. DO NOT delete files yet - preserve evidence"
        Write-Output "  3. Take screenshots of findings"
        Write-Output "`nNEXT STEPS:"
        Write-Output "  4. Run full AV scan (Windows Defender / Kaspersky / Malwarebytes)"
        Write-Output "  5. If this is a work machine: Contact IT Security immediately"
        Write-Output "  6. Assume credentials exposed - change all passwords"
        Write-Output "`nFOR CONFIRMED COMPROMISE:"
        Write-Output "  - REIMAGE the machine (cleaning is not reliable for this threat)"
        Write-Output "  - Report to: https://www.cisa.gov/report"
    } else {
        Write-Host ("`n" + ("=" * 70)) -ForegroundColor Red
        Write-Host "[!!!] INDICATORS OF COMPROMISE DETECTED!" -ForegroundColor Red
        Write-Host ("=" * 70) -ForegroundColor Red

        Write-Host "`nIOC FINDINGS ($iocCount):" -ForegroundColor Red
        foreach ($ioc in $script:IOCFindings) {
            Write-Host "  - $ioc" -ForegroundColor Red
        }

        Write-Host "`nIMMEDIATE ACTIONS:" -ForegroundColor Yellow
        Write-Host "  1. DISCONNECT from network NOW (Wi-Fi off / unplug Ethernet)" -ForegroundColor Yellow
        Write-Host "  2. DO NOT delete files yet - preserve evidence" -ForegroundColor Yellow
        Write-Host "  3. Take screenshots of findings" -ForegroundColor Yellow

        Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
        Write-Host "  4. Run full AV scan (Windows Defender / Kaspersky / Malwarebytes)" -ForegroundColor Yellow
        Write-Host "  5. If this is a work machine: Contact IT Security immediately" -ForegroundColor Yellow
        Write-Host "  6. Assume credentials exposed - change all passwords" -ForegroundColor Yellow

        Write-Host "`nFOR CONFIRMED COMPROMISE (Cobalt Strike/Chrysalis):" -ForegroundColor Red
        Write-Host "  - REIMAGE the machine (cleaning is not reliable for this threat)" -ForegroundColor Red
        Write-Host "  - Report to: https://www.cisa.gov/report" -ForegroundColor Red
    }

    $script:Results += "`n[!!!] INDICATORS OF COMPROMISE DETECTED - SEE RECOMMENDATIONS ABOVE"

} elseif ($riskCount -gt 0) {
    # Only risks found, no actual IOCs
    if ($NoColor) {
        Write-Output "`n$("=" * 70)"
        Write-Output "[~] NO IOCs FOUND - Some risk factors identified"
        Write-Output ("=" * 70)
        Write-Output "`nRISK FINDINGS ($riskCount):"
        foreach ($risk in $script:RiskFindings) { Write-Output "  - $risk" }
        Write-Output "`nThese are NOT indicators of compromise, but you should:"
        Write-Output "  - Update Notepad++ to v8.8.9+ if not already"
        Write-Output "  - Run a full AV scan as a precaution"
    } else {
        Write-Host ("`n" + ("=" * 70)) -ForegroundColor Yellow
        Write-Host "[~] NO IOCs FOUND - Some risk factors identified" -ForegroundColor Yellow
        Write-Host ("=" * 70) -ForegroundColor Yellow

        Write-Host "`nRISK FINDINGS ($riskCount):" -ForegroundColor Yellow
        foreach ($risk in $script:RiskFindings) {
            Write-Host "  - $risk" -ForegroundColor Yellow
        }

        Write-Host "`nThese are NOT indicators of compromise, but you should:" -ForegroundColor Cyan
        Write-Host "  - Update Notepad++ to v8.8.9+ if not already" -ForegroundColor Cyan
        Write-Host "  - Run a full AV scan as a precaution" -ForegroundColor Cyan
    }

} else {
    # Clean scan
    if ($NoColor) {
        Write-Output "`n$("=" * 70)"
        Write-Output "[OK] NO INDICATORS OF COMPROMISE FOUND"
        Write-Output ("=" * 70)
        Write-Output "`nYOU ARE LIKELY NOT COMPROMISED IF:"
        Write-Output "  [+] You updated Notepad++ after December 2025"
        Write-Output "  [+] You're not in targeted sectors (govt/financial in VN, PH, SV, AU)"
        Write-Output "  [+] You downloaded N++ manually from official site (not auto-update)"
        Write-Output "`nIMPORTANT CONTEXT:"
        Write-Output "  - This was a HIGHLY TARGETED attack (only ~12 machines globally)"
        Write-Output "  - Attack window: June 1 - December 2, 2025"
        Write-Output "  - Targets: Specific orgs in Vietnam, Philippines, El Salvador, Australia"
        Write-Output "`nLimitations: Attackers may have cleaned up. Run with -DeepHashScan for extended scanning."
    } else {
        Write-Host ("`n" + ("=" * 70)) -ForegroundColor Green
        Write-Host "[OK] NO INDICATORS OF COMPROMISE FOUND" -ForegroundColor Green
        Write-Host ("=" * 70) -ForegroundColor Green

        Write-Host "`nYOU ARE LIKELY NOT COMPROMISED IF:" -ForegroundColor Green
        Write-Host "  [+] You updated Notepad++ after December 2025" -ForegroundColor Green
        Write-Host "  [+] You're not in targeted sectors (govt/financial in VN, PH, SV, AU)" -ForegroundColor Green
        Write-Host "  [+] You downloaded N++ manually from official site (not auto-update)" -ForegroundColor Green

        Write-Host "`nIMPORTANT CONTEXT:" -ForegroundColor Cyan
        Write-Host "  - This was a HIGHLY TARGETED attack (only ~12 machines globally)" -ForegroundColor Cyan
        Write-Host "  - Attack window: June - December 2025" -ForegroundColor Cyan
        Write-Host "  - Targets: Specific orgs in Vietnam, Philippines, El Salvador, Australia" -ForegroundColor Cyan

        Write-Host "`nHowever, this scan has limitations:" -ForegroundColor Cyan
        Write-Host "  - Attackers may have cleaned up artifacts" -ForegroundColor Cyan
        Write-Host "  - Some logs may have rotated or been cleared" -ForegroundColor Cyan
        Write-Host "  - Network-level IOCs require router/firewall log review" -ForegroundColor Cyan

        Write-Host "`nRECOMMENDED PREVENTIVE ACTIONS:" -ForegroundColor Cyan
        Write-Host "  1. Update Notepad++ to v8.8.9+ (CRITICAL security fixes)" -ForegroundColor Cyan
        Write-Host "  2. Download ONLY from: https://notepad-plus-plus.org/downloads/" -ForegroundColor Cyan
        Write-Host "  3. Verify file integrity: Help -> About -> compare hash to GitHub" -ForegroundColor Cyan
        Write-Host "  4. Consider using the portable version (no auto-updater)" -ForegroundColor Cyan
        Write-Host "  5. Check router/DNS logs for historical connections to:" -ForegroundColor Cyan
        Write-Host "     temp.sh, cdncheck.it, safe-dns.it, self-dns.it" -ForegroundColor Cyan
        Write-Host "  6. Run a full AV scan with updated definitions" -ForegroundColor Cyan

        Write-Host "`nWARNING - BEWARE OF SCAMS:" -ForegroundColor Yellow
        Write-Host "  - Attackers may use fake 'security breach' alerts to trick you" -ForegroundColor Yellow
        Write-Host "  - NEVER download 'security scanners' from untrusted sources" -ForegroundColor Yellow
        Write-Host "  - Verify breach reports through official sources (CISA, vendor sites)" -ForegroundColor Yellow
    }
}

# Export results if requested
if ($ExportResults) {
    $textPath = "$OutputPath.txt"
    $script:Results | Out-File -FilePath $textPath -Encoding UTF8
    if ($NoColor) {
        Write-Output "`nText results exported to: $textPath"
    } else {
        Write-Host "`nText results exported to: $textPath" -ForegroundColor Cyan
    }
}

# Export JSON evidence if requested
if ($ExportJson) {
    $jsonPath = "$OutputPath.json"
    $exportData = @{
        ScanTime = Get-Date -Format "o"
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        AttackWindow = @{
            Start = $AttackStart.ToString("yyyy-MM-dd")
            End = $AttackEnd.ToString("yyyy-MM-dd")
        }
        Summary = @{
            IOCCount = $script:IOCFindings.Count
            RiskCount = $script:RiskFindings.Count
            EvidenceCount = $script:Evidence.Count
        }
        IOCFindings = $script:IOCFindings
        RiskFindings = $script:RiskFindings
        Evidence = $script:Evidence
    }
    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    if ($NoColor) {
        Write-Output "JSON evidence exported to: $jsonPath"
    } else {
        Write-Host "JSON evidence exported to: $jsonPath" -ForegroundColor Cyan
    }
}

# Footer with IoC sources
if (-not $NoColor) {
    Write-Host "`n" -NoNewline
    Write-Host "IoC Sources: Kaspersky GReAT + Rapid7 Labs (Feb 2026)" -ForegroundColor DarkGray
    Write-Host "Options: -DeepHashScan (extended), -NoColor (plain), -ExportJson (structured)" -ForegroundColor DarkGray
}

Write-Host "`n"

# ============================================================================
# EXIT CODE
# ============================================================================
# Exit code = IOC count (0 = clean, N = N IOCs found)
# Risk findings don't affect exit code (they're not compromise indicators)
exit $script:IOCFindings.Count
