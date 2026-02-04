#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Checks for indicators of compromise related to the Notepad++ supply chain attack (June-December 2025)
.DESCRIPTION
    This script checks for:
    - Suspicious directories and files
    - Known malicious file hashes (SHA1)
    - Registry autorun persistence
    - DNS cache entries for malicious domains
    - Active network connections to malicious IPs
    - DNS client event logs
    - Temp.sh related activity
.NOTES
    Based on Kaspersky's analysis published February 3, 2026
    Run as Administrator for full functionality
#>

[CmdletBinding()]
param(
    [switch]$ExportResults,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\NotepadPP_IOC_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Colors for output
$script:FindingsCount = 0
$script:Results = @()
$scanStartTime = Get-Date

function Write-Finding {
    param([string]$Message, [string]$Severity = "HIGH")
    $script:FindingsCount++
    $output = "[!] [$Severity] $Message"
    Write-Host $output -ForegroundColor Red
    $script:Results += $output
}

function Write-Clean {
    param([string]$Message)
    $output = "[OK] $Message"
    Write-Host $output -ForegroundColor Green
    $script:Results += $output
}

function Write-Info {
    param([string]$Message)
    $output = "[*] $Message"
    Write-Host $output -ForegroundColor Cyan
    $script:Results += $output
}

function Write-Section {
    param([string]$Title)
    $separator = "=" * 70
    Write-Host "`n$separator" -ForegroundColor Yellow
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "$separator" -ForegroundColor Yellow
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

# Malicious IPs
$MaliciousIPs = @(
    "45.76.155.202",
    "45.77.31.210",
    "45.32.144.255",
    "95.179.213.0",
    "59.110.7.32",
    "124.222.137.114"
)

# Suspicious directories
$SuspiciousDirectories = @(
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Bluetooth"
)

# Suspicious file names
$SuspiciousFiles = @(
    "$env:APPDATA\ProShow\load",
    "$env:APPDATA\ProShow\ProShow.exe",
    "$env:APPDATA\ProShow\defscr",
    "$env:APPDATA\ProShow\if.dnt",
    "$env:APPDATA\ProShow\proshow.crs",
    "$env:APPDATA\ProShow\proshow.phd",
    "$env:APPDATA\ProShow\proshow_e.bmp",
    "$env:APPDATA\Adobe\Scripts\alien.dll",
    "$env:APPDATA\Adobe\Scripts\alien.ini",
    "$env:APPDATA\Adobe\Scripts\lua5.1.dll",
    "$env:APPDATA\Adobe\Scripts\script.exe",
    "$env:APPDATA\Adobe\Scripts\a.txt",
    "$env:APPDATA\Bluetooth\BluetoothService.exe",
    "$env:APPDATA\Bluetooth\BluetoothService",
    "$env:APPDATA\Bluetooth\log.dll",
    "$env:LOCALAPPDATA\Temp\ns*.tmp",
    "C:\ProgramData\USOShared\*.exe"
)

# ============================================================================
# START CHECKS
# ============================================================================

Write-Host @"

    _   __      __                       __  __     __     
   / | / /___  / /____  ____  ____ _____/ /_/ /_   / /_    
  /  |/ / __ \/ __/ _ \/ __ \/ __ `/ __  / __/ _ \/ __ \   
 / /|  / /_/ / /_/  __/ /_/ / /_/ / /_/ / /_/  __/ / / /   
/_/ |_/\____/\__/\___/ .___/\__,_/\__,_/\__/\___/_/ /_/    
                    /_/                                    
    Supply Chain Attack IOC Scanner
    Based on Kaspersky GReAT Research (Feb 2026)

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
        Write-Finding "GUP.exe (auto-updater) is present - full scan recommended" "MEDIUM"
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
                Write-Finding "Version $nppVersion is BELOW 8.8.9 - UPDATE REQUIRED" "HIGH"
            } else {
                Write-Clean "Version $nppVersion is patched (8.8.9+)"
            }
        } catch {
            Write-Info "  Could not parse version automatically. Please verify manually."
        }
    }
}

# ============================================================================
# CHECK 1: Suspicious Directories
# ============================================================================
Write-Section "CHECK 1: Suspicious Directories"

foreach ($dir in $SuspiciousDirectories) {
    if (Test-Path $dir) {
        Write-Finding "Suspicious directory EXISTS: $dir"
        Write-Info "  Contents:"
        Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Info "    - $($_.Name) ($(if($_.PSIsContainer){'DIR'}else{$_.Length + ' bytes'}))"
        }
    } else {
        Write-Clean "Directory not found: $dir"
    }
}

# ============================================================================
# CHECK 2: Suspicious Files
# ============================================================================
Write-Section "CHECK 2: Suspicious Files"

foreach ($file in $SuspiciousFiles) {
    if ($file -match '\*') {
        # Handle wildcards
        # Fix: Renamed variable from $matches to $foundFiles (avoid overwriting reserved automatic variable)
        $foundFiles = Get-ChildItem -Path $file -Force -ErrorAction SilentlyContinue
        if ($foundFiles) {
            foreach ($found in $foundFiles) {
                Write-Finding "Suspicious file pattern match: $($found.FullName)"
            }
        }
    } else {
        if (Test-Path $file) {
            Write-Finding "Suspicious file EXISTS: $file"
            $fileInfo = Get-Item $file -Force
            Write-Info "  Size: $($fileInfo.Length) bytes"
            Write-Info "  Created: $($fileInfo.CreationTime)"
            Write-Info "  Modified: $($fileInfo.LastWriteTime)"
        }
    }
}

# Check for NSIS temp directories (indicator of NSIS installer execution)
$nsisTempDirs = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp" -Directory -Filter "ns*.tmp" -ErrorAction SilentlyContinue
if ($nsisTempDirs) {
    Write-Finding "NSIS temp directories found (may indicate malicious installer execution):" "MEDIUM"
    foreach ($nsisDir in $nsisTempDirs) {
        Write-Info "  - $($nsisDir.FullName) (Created: $($nsisDir.CreationTime))"
    }
} else {
    Write-Clean "No NSIS temp directories found"
}

# ============================================================================
# CHECK 3: File Hash Verification
# ============================================================================
Write-Section "CHECK 3: File Hash Verification"

$filesToHash = @()
foreach ($dir in $SuspiciousDirectories) {
    if (Test-Path $dir) {
        $filesToHash += Get-ChildItem -Path $dir -File -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# Also check common locations
$additionalPaths = @(
    "$env:LOCALAPPDATA\Temp",
    "C:\ProgramData\USOShared",
    "$env:APPDATA\Notepad++",
    "$env:PROGRAMFILES\Notepad++",
    "${env:PROGRAMFILES(x86)}\Notepad++"
)

foreach ($path in $additionalPaths) {
    if (Test-Path $path) {
        $filesToHash += Get-ChildItem -Path $path -File -Force -ErrorAction SilentlyContinue | 
            Where-Object { $_.Extension -match '\.(exe|dll|ini)$' -or $_.Name -eq 'load' -or $_.Name -eq 'BluetoothService' }
    }
}

$hashMatches = 0
if ($filesToHash.Count -gt 0) {
    Write-Info "Checking $($filesToHash.Count) files against known malicious hashes..."
    foreach ($file in $filesToHash) {
        try {
            $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $MaliciousHashes -contains $hash.ToLower()) {
                Write-Finding "MALICIOUS FILE HASH MATCH: $($file.FullName)"
                Write-Info "  SHA1: $hash"
                $hashMatches++
            }
        } catch {
            # Skip files we can't hash
        }
    }
    if ($hashMatches -eq 0) {
        Write-Clean "No known malicious file hashes found"
    }
} else {
    Write-Clean "No suspicious files to hash"
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

$suspiciousAutorunPatterns = @(
    "ProShow",
    "Adobe\\Scripts",
    "Bluetooth\\BluetoothService",
    "alien",
    "script.exe",
    "ns*.tmp"
)

foreach ($regPath in $autorunPaths) {
    if (Test-Path $regPath) {
        $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $value = $_.Value
            foreach ($pattern in $suspiciousAutorunPatterns) {
                if ($value -like "*$pattern*") {
                    Write-Finding "Suspicious autorun entry in $regPath"
                    Write-Info "  Name: $($_.Name)"
                    Write-Info "  Value: $value"
                }
            }
            # Also check for temp folder paths in autorun (IOC mentioned in article)
            if ($value -like "*\Temp\*" -or $value -like "*%TEMP%*") {
                Write-Finding "Autorun entry pointing to temp folder (suspicious):" "MEDIUM"
                Write-Info "  Path: $regPath"
                Write-Info "  Name: $($_.Name)"
                Write-Info "  Value: $value"
            }
        }
    }
}
Write-Clean "Registry autorun check completed"

# ============================================================================
# CHECK 4b: Malicious Services
# ============================================================================
Write-Section "CHECK 4b: Malicious Services"

Write-Info "Checking for suspicious Windows services..."
$suspiciousServiceFound = $false

try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        $pathName = $svc.PathName
        $svcName = $svc.Name

        # Check for suspicious service names or paths pointing to AppData/Temp
        if ($svcName -match "BluetoothService|ProShow" -or $pathName -match "AppData|\\Temp\\") {
            # Filter out legitimate system paths
            if ($pathName -notmatch "Windows\\System32|Windows\\SysWOW64|Program Files") {
                Write-Finding "Suspicious Service Found: $svcName"
                Write-Info "  Path: $pathName"
                Write-Info "  State: $($svc.State)"
                Write-Info "  Start Mode: $($svc.StartMode)"
                $suspiciousServiceFound = $true
            }
        }

        # Flag fake BluetoothService (legitimate Bluetooth runs as svchost, not standalone exe)
        if ($svcName -eq "BluetoothService" -and $pathName -notmatch "svchost") {
            Write-Finding "Suspicious BluetoothService detected (legitimate Bluetooth runs as svchost)"
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
            if ($action.Execute -match "AppData|\\Temp\\|ProShow|Bluetooth\\BluetoothService|Adobe\\Scripts") {
                Write-Finding "Suspicious Scheduled Task: $($task.TaskName)"
                Write-Info "  Path: $($task.TaskPath)"
                Write-Info "  Action: $($action.Execute)"
                Write-Info "  Arguments: $($action.Arguments)"
                Write-Info "  State: $($task.State)"
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
            if ($entry.Entry -like "*$domain*") {
                Write-Finding "MALICIOUS DOMAIN IN DNS CACHE: $($entry.Entry)"
                Write-Info "  Data: $($entry.Data)"
                Write-Info "  TTL: $($entry.TimeToLive)"
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
# CHECK 6: Active Network Connections
# ============================================================================
Write-Section "CHECK 6: Active Network Connections"

try {
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq 'Established' -or $_.State -eq 'SynSent' }
    
    $maliciousConnFound = $false
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        if ($MaliciousIPs -contains $remoteIP) {
            Write-Finding "ACTIVE CONNECTION TO MALICIOUS IP: $remoteIP"
            Write-Info "  Local Port: $($conn.LocalPort)"
            Write-Info "  Remote Port: $($conn.RemotePort)"
            Write-Info "  State: $($conn.State)"
            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                Write-Info "  Process: $($process.Name) (PID: $($conn.OwningProcess))"
            } catch {}
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
                    Write-Finding "MALICIOUS DOMAIN IN DNS LOGS: $domain"
                    Write-Info "  Time: $($event.TimeCreated)"
                    Write-Info "  Event ID: $($event.Id)"
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
                if ($line -match $ip) {
                    Write-Finding "MALICIOUS IP IN FIREWALL LOG: $ip"
                    Write-Info "  Log entry: $line"
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
                    Write-Finding "MALICIOUS DNS QUERY IN SYSMON: $queryName"
                    Write-Info "  Time: $($event.TimeCreated)"
                    $processId = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }).'#text'
                    $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
                    Write-Info "  Process: $image (PID: $processId)"
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
# CHECK 10: Running Process Analysis (with File Location Verification)
# ============================================================================
Write-Section "CHECK 10: Running Process Analysis"

$suspiciousProcessNames = @(
    "ProShow",
    "script",
    "BluetoothService",
    "alien",
    "AutoUpdater"
)

$suspiciousProcessPaths = @(
    "$env:APPDATA\ProShow",
    "$env:APPDATA\Adobe\Scripts",
    "$env:APPDATA\Bluetooth",
    "$env:LOCALAPPDATA\Temp"
)

# Legitimate paths for processes that might have suspicious names
$legitimatePaths = @{
    "BluetoothService" = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")
}

$processes = Get-Process -ErrorAction SilentlyContinue
$suspiciousProcessFound = $false

foreach ($proc in $processes) {
    # Check process names
    foreach ($name in $suspiciousProcessNames) {
        if ($proc.Name -like "*$name*") {
            try {
                $path = $proc.MainModule.FileName
                
                # Special handling for BluetoothService - check if it's in legitimate location
                if ($proc.Name -eq "BluetoothService") {
                    $isLegit = $false
                    foreach ($legitPath in $legitimatePaths["BluetoothService"]) {
                        if ($path -like "$legitPath*") {
                            $isLegit = $true
                            break
                        }
                    }
                    if ($isLegit) {
                        Write-Info "BluetoothService running from legitimate location: $path"
                        continue
                    } else {
                        Write-Finding "BluetoothService running from SUSPICIOUS location!"
                        Write-Info "  Expected: System32 or SysWOW64"
                        Write-Info "  Actual: $path"
                        Write-Info "  PID: $($proc.Id)"
                        $suspiciousProcessFound = $true
                    }
                } else {
                    Write-Finding "Suspicious process running: $($proc.Name)"
                    Write-Info "  PID: $($proc.Id)"
                    Write-Info "  Path: $path"
                    Write-Info "  Start Time: $($proc.StartTime)"
                    $suspiciousProcessFound = $true
                }
            } catch {
                Write-Finding "Suspicious process (couldn't get path): $($proc.Name)"
                Write-Info "  PID: $($proc.Id)"
                $suspiciousProcessFound = $true
            }
        }
    }
    
    # Check process paths
    try {
        $procPath = $proc.MainModule.FileName
        foreach ($suspPath in $suspiciousProcessPaths) {
            if ($procPath -like "$suspPath*") {
                # Exclude common legitimate temp executables
                if ($procPath -notmatch "\\(msi|setup|install).*\.exe$") {
                    Write-Finding "Process running from suspicious path: $procPath"
                    Write-Info "  Process: $($proc.Name) (PID: $($proc.Id))"
                    Write-Info "  Start Time: $($proc.StartTime)"
                    $suspiciousProcessFound = $true
                }
            }
        }
    } catch {}
}

# Specific check: Is GUP.exe currently running and what did it spawn?
$gupProcesses = Get-Process -Name "GUP" -ErrorAction SilentlyContinue
if ($gupProcesses) {
    Write-Info "GUP.exe (Notepad++ updater) is currently running"
    foreach ($gup in $gupProcesses) {
        Write-Info "  PID: $($gup.Id)"
        try {
            Write-Info "  Path: $($gup.MainModule.FileName)"
        } catch {}
    }
    Write-Info "  Note: Check if any suspicious child processes were spawned"
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
                Write-Finding "MALICIOUS COMMAND PATTERN IN POWERSHELL HISTORY"
                Write-Info "  Line $lineNum`: $line"
                Write-Info "  Pattern: $pattern"
                $maliciousHistoryFound = $true
            }
        }
        # Also check for temp.sh references
        if ($line -match "temp\.sh") {
            Write-Finding "Reference to temp.sh found in PowerShell history"
            Write-Info "  Line $lineNum`: $line"
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
                    Write-Finding "Malicious command in Run history: $cmd"
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
            Write-Finding "Reconnaissance output file found: $searchPath"
            Write-Info "  This file may contain exfiltrated system info"
        }
    }
}

# ============================================================================
# CHECK 12: Notepad++ Security Log (v8.9+)
# ============================================================================
Write-Section "CHECK 12: Notepad++ Security Error Log"

$securityLogPath = "$env:LOCALAPPDATA\Notepad++\log\securityError.log"

if (Test-Path $securityLogPath) {
    Write-Finding "securityError.log EXISTS - update verification failures detected" "MEDIUM"
    Write-Info "Log location: $securityLogPath"
    Write-Info "Last 20 lines of security log:"
    Get-Content $securityLogPath -Tail 20 | ForEach-Object {
        Write-Info "  $_"
    }
} else {
    Write-Clean "No securityError.log found (good - no update verification failures, or older Notepad++ version)"
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
                Write-Finding "Suspicious file in $dlPath`: $($file.Name)" "MEDIUM"
                Write-Info "  Full path: $($file.FullName)"
                Write-Info "  Created: $($file.CreationTime)"
                Write-Info "  Size: $($file.Length) bytes"
                try {
                    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA1).Hash
                    Write-Info "  SHA1: $hash"
                    if ($MaliciousHashes -contains $hash.ToLower()) {
                        Write-Finding "MALICIOUS HASH MATCH: $($file.FullName)"
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
        Write-Finding "SUSPICIOUS FILE IN TEMP: $tempFile"
        $fileInfo = Get-Item $tempFile
        Write-Info "  Created: $($fileInfo.CreationTime)"
        Write-Info "  Modified: $($fileInfo.LastWriteTime)"
        Write-Info "  Size: $($fileInfo.Length) bytes"
        try {
            $hash = (Get-FileHash -Path $tempFile -Algorithm SHA1).Hash
            Write-Info "  SHA1: $hash"
            if ($MaliciousHashes -contains $hash.ToLower()) {
                Write-Finding "CONFIRMED MALICIOUS: Hash matches known IOC"
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
        
        # Check if created during attack window (June-Dec 2025)
        $attackStart = [DateTime]"2025-06-01"
        $attackEnd = [DateTime]"2025-12-31"
        if ($nsisDir.CreationTime -ge $attackStart -and $nsisDir.CreationTime -le $attackEnd) {
            Write-Finding "NSIS directory created during attack window (June-Dec 2025)" "MEDIUM"
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
                    Write-Finding "Suspicious process creation detected"
                    Write-Info "  Time: $($event.TimeCreated)"
                    Write-Info "  Pattern matched: $pattern"
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
                Write-Finding "Suspicious PowerShell activity detected"
                Write-Info "  Time: $($event.TimeCreated)"
                Write-Info "  Event ID: $($event.Id)"
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
                    Write-Finding "Notepad++ version is below 8.8.9 - CRITICAL: UPDATE IMMEDIATELY" "HIGH"
                    Write-Info "  Version 8.8.9+ includes critical security fixes for this attack"
                    Write-Info "  Download from: https://notepad-plus-plus.org/downloads/"
                } elseif ($vCurrent -lt $vSecure) {
                    Write-Finding "Notepad++ version is below 8.9 - RECOMMEND UPDATE" "MEDIUM"
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
            $gupHash = (Get-FileHash -Path $gupExe -Algorithm SHA256).Hash
            Write-Info "  GUP SHA256: $gupHash"
        }
        
        # Check for any update.exe files
        $updateFiles = Get-ChildItem -Path $nppPath -Recurse -Filter "update*.exe" -ErrorAction SilentlyContinue
        foreach ($updateFile in $updateFiles) {
            Write-Info "  Update file found: $($updateFile.FullName)"
            $hash = (Get-FileHash -Path $updateFile.FullName -Algorithm SHA1).Hash
            Write-Info "    SHA1: $hash"
            if ($MaliciousHashes -contains $hash.ToLower()) {
                Write-Finding "MALICIOUS UPDATE FILE DETECTED: $($updateFile.FullName)"
            }
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
        Write-Info "-" * 50
        
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

$summary = @"
Scan completed at: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Scan Duration: $([math]::Round(((Get-Date) - $scanStartTime).TotalSeconds, 2)) seconds

Total findings: $($script:FindingsCount)
"@

Write-Host $summary
$script:Results += $summary

if ($script:FindingsCount -gt 0) {
    Write-Host "`n" + "=" * 70 -ForegroundColor Red
    Write-Host "[!!!] POTENTIAL COMPROMISE INDICATORS FOUND!" -ForegroundColor Red
    Write-Host "=" * 70 -ForegroundColor Red
    
    Write-Host "`nIMMEDIATE ACTIONS:" -ForegroundColor Yellow
    Write-Host "  1. DISCONNECT from network NOW (Wi-Fi off / unplug Ethernet)" -ForegroundColor Yellow
    Write-Host "  2. DO NOT delete files yet - preserve evidence" -ForegroundColor Yellow
    Write-Host "  3. Take screenshots of findings" -ForegroundColor Yellow
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  4. Run full AV scan (Windows Defender / Kaspersky / Malwarebytes)" -ForegroundColor Yellow
    Write-Host "  5. Use Microsoft Defender Offline Scan for deeper analysis" -ForegroundColor Yellow
    Write-Host "  6. If this is a work machine: Contact IT Security immediately" -ForegroundColor Yellow
    Write-Host "  7. Assume credentials exposed - prepare to change passwords:" -ForegroundColor Yellow
    Write-Host "     - Email, Password Manager, GitHub, VPN, Cloud services" -ForegroundColor Yellow
    
    Write-Host "`nFOR CONFIRMED COMPROMISE (Cobalt Strike/Chrysalis backdoor):" -ForegroundColor Red
    Write-Host "  - REIMAGE the machine (cleaning is not reliable for this threat)" -ForegroundColor Red
    Write-Host "  - After rebuild: Reinstall Notepad++ v8.8.9+ from official site" -ForegroundColor Red
    Write-Host "  - Consider professional incident response if org/sensitive data" -ForegroundColor Red
    
    $script:Results += "`n[!!!] POTENTIAL COMPROMISE INDICATORS FOUND - SEE RECOMMENDATIONS ABOVE"
} else {
    Write-Host "`n" + "=" * 70 -ForegroundColor Green
    Write-Host "[OK] NO INDICATORS OF COMPROMISE FOUND" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Green
    
    Write-Host "`nYOU ARE LIKELY NOT COMPROMISED IF:" -ForegroundColor Green
    Write-Host "  [+] You updated Notepad++ after December 2025" -ForegroundColor Green
    Write-Host "  [+] You're not in targeted sectors (govt/financial in VN, PH, SV, AU)" -ForegroundColor Green
    Write-Host "  [+] You downloaded N++ manually from official site (not auto-update)" -ForegroundColor Green
    Write-Host "  [+] No IOCs were found above" -ForegroundColor Green
    
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

# Export results if requested
if ($ExportResults) {
    $script:Results | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Cyan
}

Write-Host "`n"