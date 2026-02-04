# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains `nppcheck.ps1`, a PowerShell IOC (Indicators of Compromise) scanner for detecting the Notepad++ supply chain attack that occurred between June-December 2025. The script is based on Kaspersky GReAT research published February 2026.

## Running the Script

```powershell
# Basic scan (requires Administrator)
.\nppcheck.ps1

# Export results to file
.\nppcheck.ps1 -ExportResults

# Custom output path
.\nppcheck.ps1 -ExportResults -OutputPath "C:\path\to\report.txt"
```

The script requires Administrator privileges (`#Requires -RunAsAdministrator`).

## Architecture

The script performs 19 sequential security checks:

1. **Quick Triage** - Checks if Notepad++ is installed and assesses risk level
2. **Suspicious Directories** - Scans for known malware staging directories (`%APPDATA%\ProShow`, `%APPDATA%\Adobe\Scripts`, `%APPDATA%\Bluetooth`)
3. **Suspicious Files** - Checks for specific malicious file artifacts
4. **File Hash Verification** - Compares file SHA1 hashes against known malicious IOCs
5. **Registry Autorun** - Checks persistence mechanisms in Run/RunOnce keys
6. **Malicious Services** (4b) - Checks for suspicious Windows services pointing to non-system paths
7. **Scheduled Tasks** (4c) - Checks for scheduled tasks with suspicious actions
8. **DNS Cache** - Searches for malicious C2 domains
9. **Active Network Connections** - Detects live connections to known malicious IPs
10. **DNS Client Event Logs** - Reviews DNS resolution history
11. **Firewall Logs** - Analyzes Windows Firewall logs for malicious IPs
12. **Sysmon DNS Logs** - Checks Sysmon Event ID 22 for DNS queries
13. **Running Processes** - Identifies suspicious running processes
14. **Command History** - Searches PowerShell/CMD history for attack patterns
15. **Notepad++ Security Log** - Checks for update verification failures (v8.9+)
16. **Downloads Folder** - Scans for suspicious downloaded executables
17. **Temp Folder** - Analyzes NSIS installer remnants
18. **Event Viewer** - Checks process creation events (4688) and PowerShell logs
19. **Notepad++ Installation** - Deep analysis with hash verification

## Key Data Structures

- `$MaliciousHashes` - Array of 28 known malicious SHA1 hashes
- `$MaliciousDomains` - Array of C2 domains (cdncheck.it, safe-dns.it, temp.sh, etc.)
- `$MaliciousIPs` - Array of 6 known attacker IPs
- `$SuspiciousDirectories` and `$SuspiciousFiles` - Filesystem IOCs

## Output Functions

- `Write-Finding` - Red output for detected IOCs (increments `$script:FindingsCount`)
- `Write-Clean` - Green output for passed checks
- `Write-Info` - Cyan informational output
- `Write-Section` - Yellow section headers

All output is accumulated in `$script:Results` for optional export.
