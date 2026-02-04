# Notepad++ Supply Chain Attack IOC Scanner

A PowerShell-based Indicators of Compromise (IOC) scanner for detecting the Notepad++ supply chain attack that occurred between June-December 2025.

```
    _   __      __                       __  __     __
   / | / /___  / /____  ____  ____ _____/ /_/ /_   / /_
  /  |/ / __ \/ __/ _ \/ __ \/ __ `/ __  / __/ _ \/ __ \
 / /|  / /_/ / /_/  __/ /_/ / /_/ / /_/ / /_/  __/ / / /
/_/ |_/\____/\__/\___/ .___/\__,_/\__,_/\__/\___/_/ /_/
                    /_/
    Supply Chain Attack IOC Scanner
```

## Disclaimer

**USE AT YOUR OWN RISK**

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

By using this script, you acknowledge and agree that:

- **The author(s) are NOT responsible** for any damage, data loss, system instability, or any other negative consequences that may result from running this script
- This tool is provided for **educational and defensive security purposes only**
- You are **solely responsible** for reviewing the code before execution and understanding what it does
- You should **test this script in a non-production environment** before running it on critical systems
- This script requires **Administrator privileges** and accesses sensitive system areas (registry, services, event logs, etc.)
- **False positives may occur** - findings should be verified manually before taking remediation actions
- The IOC data is based on publicly available threat intelligence and may not be complete or up-to-date

**If you do not agree with these terms, do not use this software.**

---

## Background

In February 2026, Kaspersky's Global Research and Analysis Team (GReAT) published research detailing a sophisticated supply chain attack targeting Notepad++ users. The attack exploited the GUP (Generic Updater Platform) auto-update mechanism to deliver malware to targeted victims.

### Attack Timeline
- **June 2025**: Attack campaign begins
- **December 2025**: Attack campaign ends
- **February 2026**: Public disclosure by Kaspersky

### Targeted Regions & Sectors
This was a **highly targeted attack** affecting approximately 12 machines globally, primarily:
- Government organizations
- Financial institutions
- Regions: Vietnam, Philippines, El Salvador, Australia

### Attack Chain Overview
1. Attacker compromises Notepad++ update infrastructure
2. Malicious update delivered via GUP.exe (auto-updater)
3. Dropper installs persistence mechanisms
4. Cobalt Strike / Chrysalis backdoor deployed
5. Data exfiltration via temp.sh and other C2 channels

## Features

This scanner performs **22 comprehensive security checks**:

| Check | Description |
|-------|-------------|
| Quick Triage | Risk assessment based on N++ installation and version |
| Suspicious Directories | Scans for known malware staging directories |
| Suspicious Files | Checks for specific malicious file artifacts |
| SHA-1 Hash Verification | Compares SHA-1 hashes against 28 known IOCs (Kaspersky) |
| SHA-256 Hash Scan | Compares SHA-256 hashes against 16 Rapid7 Chrysalis IOCs |
| Registry Autorun | Checks Run/RunOnce persistence mechanisms |
| Malicious Services | Detects suspicious Windows services |
| Scheduled Tasks | Checks for malicious scheduled task persistence |
| DNS Cache | Searches for malicious C2 domains |
| Hosts File | Checks for C2 domain entries in hosts file |
| TCP Connections | Detects live TCP connections to known malicious IPs |
| Netstat Scan | Broader protocol scan for C2 IPs |
| DNS Event Logs | Reviews DNS resolution history |
| Firewall Logs | Analyzes Windows Firewall logs |
| Sysmon DNS Logs | Checks Sysmon Event ID 22 (if installed) |
| Running Processes | Identifies suspicious running processes |
| Command History | Searches for attack command patterns |
| N++ Security Log | Checks for update verification failures |
| Downloads Folder | Scans for suspicious executables |
| Temp Folder | Analyzes NSIS installer remnants |
| Event Viewer | Checks process creation and PowerShell logs |
| N++ Installation | Deep analysis with integrity verification |

## Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1** or later
- **Administrator privileges** (required)
- Optional: Sysmon installed for enhanced DNS query logging

## Installation

### Option 1: Clone the Repository
```powershell
git clone https://github.com/maremmano/nppcheck.git
cd nppcheck
```

### Option 2: Download Directly
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/maremmano/nppcheck/main/nppcheck.ps1" -OutFile "nppcheck.ps1"
```

## Usage

### Basic Scan
```powershell
# Open PowerShell as Administrator
# Navigate to the script directory

# If needed, temporarily allow script execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Run the scanner
.\nppcheck.ps1
```

### Export Results to File
```powershell
.\nppcheck.ps1 -ExportResults
```
Results will be saved to your Desktop as `NotepadPP_IOC_Report_<timestamp>.txt`

### Custom Output Path
```powershell
.\nppcheck.ps1 -ExportResults -OutputPath "C:\SecurityReports\npp_scan.txt"
```

### Deep Hash Scan
Extends SHA-256 scanning to Downloads, Temp, and ProgramData directories:
```powershell
.\nppcheck.ps1 -DeepHashScan
```

### Plain Text Output (for logging/automation)
```powershell
.\nppcheck.ps1 -NoColor | Out-File scan_results.txt
```

### Combined Options
```powershell
.\nppcheck.ps1 -DeepHashScan -ExportResults -NoColor
```

### Exit Codes
The script returns the number of findings as the exit code (useful for CI/automation):
- `0` = No indicators of compromise found
- `N` = N alerts detected

## Understanding the Output

### Color Coding
- **Red `[!]`** - Finding detected (potential IOC)
- **Green `[OK]`** - Check passed (clean)
- **Cyan `[*]`** - Informational message
- **Yellow** - Section headers

### Severity Levels
- **HIGH** - Strong indicator of compromise, immediate action recommended
- **MEDIUM** - Suspicious finding, warrants investigation

## Known IOCs Checked

### Malicious Domains (C2)
- `cdncheck.it` / `cdncheck.it.com`
- `self-dns.it` / `self-dns.it.com`
- `safe-dns.it` / `safe-dns.it.com`
- `api.wiresguard.com` / `wiresguard.com`
- `api.skycloudcenter.com` / `skycloudcenter.com`
- `temp.sh`

### Malicious IPs
- `45.76.155.202`
- `45.77.31.210`
- `45.32.144.255`
- `95.179.213.0`
- `59.110.7.32`
- `124.222.137.114`
- `61.4.102.97`

### Suspicious Directories
- `%APPDATA%\ProShow`
- `%APPDATA%\Adobe\Scripts`
- `%APPDATA%\Bluetooth`

### Suspicious Files
- `ProShow.exe`, `load`, `defscr`, `if.dnt`
- `alien.dll`, `alien.ini`, `script.exe`
- `BluetoothService.exe`, `log.dll`

## What To Do If Compromised

If the scanner reports findings:

### Immediate Actions
1. **DISCONNECT** from the network immediately
2. **DO NOT** delete files - preserve evidence
3. **Take screenshots** of all findings

### Next Steps
4. Run a full antivirus scan (Windows Defender, Kaspersky, Malwarebytes)
5. Consider Microsoft Defender Offline Scan
6. If corporate machine: **Contact IT Security immediately**
7. Assume credentials are compromised - prepare to change all passwords

### For Confirmed Compromise
- **REIMAGE the machine** - cleaning is not reliable for this threat
- After rebuild: Install Notepad++ v8.8.9+ from official site only
- Consider professional incident response for sensitive environments

## Limitations

- Attackers may have cleaned up artifacts
- Some logs may have rotated or been cleared
- Network-level IOCs require router/firewall log review
- Cannot detect all variants or future modifications
- False positives are possible

## Prevention Recommendations

1. **Update Notepad++** to version 8.8.9 or later
2. Download **ONLY** from official site: https://notepad-plus-plus.org/downloads/
3. Verify file integrity via Help > About (compare hash to GitHub releases)
4. Consider using the **portable version** (no auto-updater)
5. Enable DNS logging and Sysmon for better visibility
6. Review router/firewall logs for connections to known malicious domains

## References

- [Kaspersky GReAT Research - February 2026](https://securelist.com/) (when available)
- [Rapid7 Labs - The Chrysalis Backdoor](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- [Notepad++ Official Downloads](https://notepad-plus-plus.org/downloads/)
- [Notepad++ GitHub Releases](https://github.com/notepad-plus-plus/notepad-plus-plus/releases)
- [CISA Incident Reporting](https://www.cisa.gov/report)

## Contributing

Contributions are welcome! If you have additional IOCs, improvements, or bug fixes:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see below:

```
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Author

Created for the security community to help identify potential victims of the Notepad++ supply chain attack.

---

**Remember: When in doubt, reimage. No scanner can guarantee 100% detection of sophisticated threats.**
