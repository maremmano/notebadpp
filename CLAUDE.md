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

# Deep hash scan (extends to Downloads, Temp, ProgramData)
.\nppcheck.ps1 -DeepHashScan

# Plain text output for logging/automation
.\nppcheck.ps1 -NoColor | Out-File scan.txt

# Custom output path
.\nppcheck.ps1 -ExportResults -OutputPath "C:\path\to\report.txt"
```

The script requires Administrator privileges (`#Requires -RunAsAdministrator`).
Exit code equals the number of findings (0 = clean).

## Architecture

The script performs 22 sequential security checks:

1. **Quick Triage** - Checks if Notepad++ is installed and assesses risk level
2. **Suspicious Directories** - Scans for known malware staging directories
3. **Suspicious Files** - Checks for specific malicious file artifacts
4. **SHA-1 Hash Verification** - Compares SHA-1 hashes against 28 Kaspersky IOCs
5. **SHA-256 Hash Scan** (3b) - Compares SHA-256 against 16 Rapid7 Chrysalis IOCs
6. **Registry Autorun** - Checks persistence mechanisms in Run/RunOnce keys
7. **Malicious Services** (4b) - Checks for suspicious Windows services
8. **Scheduled Tasks** (4c) - Checks for scheduled tasks with suspicious actions
9. **DNS Cache** - Searches for malicious C2 domains
10. **Hosts File** (5b) - Checks hosts file for C2 domain entries
11. **TCP Connections** - Detects live TCP connections to known malicious IPs
12. **Netstat Scan** (6b) - Broader protocol scan for C2 IPs
13. **DNS Client Event Logs** - Reviews DNS resolution history
14. **Firewall Logs** - Analyzes Windows Firewall logs for malicious IPs
15. **Sysmon DNS Logs** - Checks Sysmon Event ID 22 for DNS queries
16. **Running Processes** - Identifies suspicious running processes
17. **Command History** - Searches PowerShell/CMD history for attack patterns
18. **Notepad++ Security Log** - Checks for update verification failures (v8.9+)
19. **Downloads Folder** - Scans for suspicious downloaded executables
20. **Temp Folder** - Analyzes NSIS installer remnants
21. **Event Viewer** - Checks process creation events (4688) and PowerShell logs
22. **Notepad++ Installation** - Deep analysis with hash verification

## Key Data Structures

- `$MaliciousHashes` - Array of 28 known malicious SHA-1 hashes (Kaspersky)
- `$Rapid7FileIndicators` - Array of 16 SHA-256 file indicators with descriptions (Rapid7)
- `$Rapid7Hashes` - Extracted SHA-256 hashes for matching
- `$MaliciousDomains` - Array of C2 domains (cdncheck.it, safe-dns.it, temp.sh, etc.)
- `$MaliciousIPs` - Array of 7 known attacker IPs (Kaspersky + Rapid7)
- `$SuspiciousDirectories` and `$SuspiciousFiles` - Filesystem IOCs

## Output Functions

- `Write-Finding` - Red output for detected IOCs (increments `$script:FindingsCount`)
- `Write-Clean` - Green output for passed checks
- `Write-Info` - Cyan informational output
- `Write-Section` - Yellow section headers

All output is accumulated in `$script:Results` for optional export.
