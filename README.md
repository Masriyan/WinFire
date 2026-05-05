# WinFire

**Windows Forensic Incident Response Engine v2.0.2**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%2FServer%202016%2B-green.svg)](https://www.microsoft.com/windows)
[![Version](https://img.shields.io/badge/Version-2.0.2-brightgreen.svg)](https://github.com/Masriyan/WinFire)

> An enterprise-grade PowerShell tool for Windows digital forensics and incident response, designed to rapidly collect critical forensic artifacts for security investigations.

## Table of Contents

- [Before You Use](#before-you-use)
- [How WinFire Works](#how-winfire-works)
- [What's New in v2.0.2](#whats-new-in-v202)
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Collected Artifacts](#collected-artifacts)
- [Output Structure](#output-structure)
- [Examples](#examples)
- [Legal Considerations](#legal-considerations)
- [Contributing](#contributing)
- [Security](#security)
- [Changelog](#changelog)
- [License](#license)

## Before You Use

> **Antivirus/EDR Detection Warning**
>
> WinFire **will likely be detected** by antivirus software and EDR solutions. This is expected behavior because the script:
>
> - Accesses security-sensitive registry keys (persistence mechanisms)
> - Enumerates all running processes with command lines
> - Collects credential-related artifacts (LSASS indicators, SAM/SECURITY)
> - Reads browser data and user activity traces
> - Performs operations similar to threat actor reconnaissance

### How to Handle AV Detection

**Option 1: Add Exclusion (Recommended)**

```powershell
# Add folder exclusion in Windows Defender
Add-MpPreference -ExclusionPath "C:\Path\To\WinFire"
```

**Option 2: Temporarily Disable Real-Time Protection**

```powershell
# Disable temporarily (requires Admin)
Set-MpPreference -DisableRealtimeMonitoring $true

# Run WinFire
.\WinFire.ps1 -Full -OutputPath "C:\Forensics"

# Re-enable immediately after
Set-MpPreference -DisableRealtimeMonitoring $false
```

> **Document any AV exclusions or modifications** in your chain of custody notes for forensic integrity.

## How WinFire Works

### Execution Flow

```
START
  |
  v
[Show Banner] -- Displays version, hostname, user, PS version, OS
  |
  v
[Prerequisites Check] -- Validates PS >= 5.1, Windows OS
  |  Fail --> EXIT (code 2)
  v
[Admin Privileges Check] -- Verifies Administrator role + forensic privileges
  |  Fail --> Warning (non-fatal)
  v
[Initialize Output Directory] -- Creates timestamped results folder
  |
  v
[Start Transcript] -- Full PowerShell transcript logging
  |
  v
[Chain of Custody] -- Records case metadata, system context
  |
  v
  +-- Phase 1/6: System Baseline
  |     System Info, User Accounts, Process & Service Analysis
  |
  +-- Phase 2/6: Network Analysis
  |     TCP/UDP Connections, Firewall, SMB, RDP
  |
  +-- Phase 3/6: File System & Registry
  |     Amcache, Prefetch, SRUM, Autoruns, USB History
  |
  +-- Phase 4/6: Event Logs & Browser Forensics
  |     Security/System/Application Logs, Chrome/Edge/Firefox
  |
  +-- Phase 5/6: Advanced Threat Detection
  |     LOLBAS, Credentials, Defender Exclusions, Threat Score
  |
  +-- Phase 6/6: Report Generation
  |     HTML Report, Hash Manifest, Evidence ZIP
  |
  v
[Execution Summary] -- Status, duration, operations count, output path
  |
  v
[Stop Transcript] --> EXIT (code 0 or 1)
```

### Output Structure

```
WinFire_Results_YYYYMMDD_HHMMSS/
|-- Raw_Data/                          # Structured data (30+ files)
|   |-- System_Information.csv/.json
|   |-- Running_Processes.csv/.json
|   |-- LOLBAS_Detection.csv/.json
|   |-- Credential_Indicators.csv/.json
|   |-- Threat_Score.csv/.json
|   +-- ...
|
|-- Collected_Artifacts/               # Binary artifacts
|   |-- Browser_Profiles/
|   |-- PowerShell_History/
|   |-- JumpLists/
|   |-- Amcache.hve
|   |-- Prefetch/
|   +-- Timeline/
|
|-- Reports/
|   |-- WinFire_Executive_Summary.html
|   |-- Chain_Of_Custody.json
|   |-- Hash_Manifest.txt
|   +-- Operation_Metrics.csv          # Per-operation timing
|
|-- WinFire_ExecutionLog.txt           # Detailed log
+-- WinFire_Transcript.txt            # Full PS transcript
```

### Risk Level Guide

| Score  | Level        | Action Required                              |
| ------ | ------------ | -------------------------------------------- |
| 0-10   | **Low**      | Routine findings, standard review            |
| 11-30  | **Medium**   | Notable findings, investigate warnings       |
| 31-60  | **High**     | Significant threats, prioritize analysis     |
| 61-100 | **Critical** | Active compromise likely, immediate response |

## What's New in v2.0.2

### Enterprise-Grade Improvements

| Feature                      | Description                                                               |
| ---------------------------- | ------------------------------------------------------------------------- |
| **Centralized Version**      | Single `$script:Version` constant, no more hardcoded strings              |
| **Prerequisites Validation** | Checks PS version >= 5.1 and Windows OS before scan                       |
| **Professional Banner**      | Shows hostname, user, privilege level, PS version, OS, start time         |
| **Phased Execution**         | 6 named phases with clear log markers                                     |
| **Operation Metrics**        | Per-operation timing via Stopwatch, exported to `Operation_Metrics.csv`   |
| **Transcript Logging**       | Full PowerShell transcript to `WinFire_Transcript.txt`                    |
| **Graceful Shutdown**        | Cancellation flag checked before each operation                           |
| **Exit Codes**               | `0` = success, `1` = error, `2` = prerequisites failed                   |
| **Execution Summary**        | Professional summary table with status, duration, operation counts        |
| **Variable Scope Fix**       | Renamed `$script:OutputPath` to `$script:ResultsPath` (root cause fix)   |
| **StrictMode Safety**        | All variables properly initialized before use                             |
| **ASCII-Only Output**        | No Unicode characters that break Windows PowerShell 5.1 encoding          |

### Bug Fixes (v2.0.2)

- **Fixed variable scope collision**: `$script:OutputPath = $null` was overwriting the `$OutputPath` parameter
- **Fixed StrictMode violation**: `$oldErrorActionPreference` moved before `try` block
- **Added parameter validation**: `[ValidateNotNullOrEmpty()]` on `$BasePath`
- **Wrapped admin check in try/catch**: Prevents cascading failures
- **Replaced Unicode characters**: All box-drawing characters replaced with ASCII
- **Renamed unapproved verb**: `Log-WinFireMessage` renamed to `Write-WinFireLog`
- **Fixed automatic variable conflicts**: `$profile` -> `$userProfile`, `$event` -> `$logEvent`
- **Removed unused variables**: `$dnsEntries`, `$persistenceKeys`, `$hash`
- **Fixed null comparisons**: `$null` moved to left side of equality checks

### Previous Releases

- **v2.0.1** - Startup bug fixes (banner parsing, privilege checks, logging init order)
- **v2.0.0** - Major update with 10 new threat detection features
- **v1.0.0** - Initial release with core forensic collection

## Overview

WinFire is an enterprise-grade PowerShell script designed for incident responders, digital forensics investigators, and cybersecurity professionals. It rapidly collects critical forensic artifacts from Windows systems, providing structured output in multiple formats (CSV, JSON, HTML) for immediate analysis or integration with other forensic tools.

### Key Capabilities

- **Rapid Artifact Collection**: Efficiently gathers evidence from running systems
- **Threat Detection**: Active threat hunting with LOLBAS, credential, and process analysis
- **Automated Scoring**: System-wide threat assessment with risk levels
- **Chain of Custody**: Maintains forensic integrity with proper documentation
- **Multi-Format Output**: CSV, JSON, and HTML reports for various analysis workflows
- **Evidence Integrity**: Cryptographic hashing ensures artifact authenticity
- **Operation Metrics**: Per-task timing for performance analysis and audit trails

## Features

### Threat Detection (v2.0+)

- LOLBAS (Living-Off-The-Land Binary) abuse detection
- Credential harvesting/dumping indicators
- Suspicious process parent-child relationships
- Windows Defender exclusion analysis
- PowerShell command history with threat patterns
- RDP lateral movement detection
- Automated threat scoring (0-100)

### System Analysis

- Operating system and hardware information
- Installed software inventory
- Environment variables and system paths
- Network configuration and interfaces

### User Activity Tracking

- Local user accounts and group memberships
- User profile artifacts and recent file access
- Registry-based user activity (UserAssist, ShellBags)
- Windows Timeline database collection
- Jump List analysis
- LNK file parsing

### Process & Service Analysis

- Running processes with command lines and hashes
- Windows services and startup configurations
- Scheduled tasks enumeration
- WMI event subscriptions (persistence mechanism)
- Advanced process tree analysis

### Network Forensics

- Active network connections (TCP/UDP)
- Listening ports and associated processes
- Network shares and mapped drives
- Windows Firewall rules
- SMB sessions and open files
- RDP connection history

### File System Artifacts

- Recently modified files in critical locations
- Suspicious file detection based on extensions/attributes
- Startup folder contents
- **Amcache.hve** - Application execution artifacts
- **Prefetch files** - Program execution evidence
- **SRUM database** - System resource usage monitoring
- **BITS jobs** - Background transfer service activity

### Registry Analysis

- Autorun/persistence registry keys
- USB device history
- Recent documents and MRU lists
- COM hijacking indicators
- Network drive history

### Event Log Collection

- Security events (logons, privilege use, account changes)
- System events (service changes, boot/shutdown)
- Application crash events
- PowerShell operational logs
- Windows Defender detection events

### Browser Forensics

- Chrome, Edge, and Firefox profile collection
- Robust handling of locked browser files using RoboCopy
- Cache and history databases for offline analysis

### Security Tool Detection

- Windows Defender status and configuration
- Defender exclusion analysis
- Installed antivirus products detection
- EDR/XDR agent identification
- PowerShell logging configuration analysis

### Memory Analysis Indicators

- Loaded DLL enumeration
- Process hollowing indicators
- DLL injection detection
- Suspicious process identification

## Prerequisites

### System Requirements

- **Operating System**: Windows 10, Windows 11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher (validated at startup)
- **Privileges**: Administrator rights required
- **Disk Space**: Minimum 1GB free space (varies by system activity)

### Recommended Privileges

WinFire automatically checks for and benefits from these privileges:

- `SeDebugPrivilege` - Access to all processes
- `SeBackupPrivilege` - Read access to all files
- `SeRestorePrivilege` - Restore file attributes

## Installation

### Method 1: Direct Download

1. Download the `WinFire.ps1` script from the [releases page](https://github.com/Masriyan/WinFire/releases)
2. Place it in your forensic toolkit directory
3. Verify the script hash against published checksums

### Method 2: Git Clone

```powershell
git clone https://github.com/Masriyan/WinFire
cd WinFire
```

### Execution Policy

```powershell
# Temporarily allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## Usage

### Basic Syntax

```powershell
.\WinFire.ps1 [-Quick] [-Full] [-OutputPath <Path>] [-CaseNumber <String>]
              [-Investigator <String>] [-Purpose <String>] [-HashAlgorithm <String>]
              [-ExcludeNetwork] [-ExcludeBrowser] [-Quiet] [-Help]
```

### Parameters

| Parameter         | Description                                           | Default                     |
| ----------------- | ----------------------------------------------------- | --------------------------- |
| `-Quick`          | Performs rapid scan focusing on high-impact artifacts | False                       |
| `-Full`           | Comprehensive scan collecting all available artifacts | True (if neither specified) |
| `-OutputPath`     | Custom directory for output files                     | Current directory           |
| `-CaseNumber`     | Forensic case number for chain of custody             | "N/A"                       |
| `-Investigator`   | Name of the investigator                              | "WinFire User"              |
| `-Purpose`        | Investigation purpose description                     | "General Forensic Scan"     |
| `-HashAlgorithm`  | Hashing algorithm (MD5, SHA1, SHA256)                 | SHA256                      |
| `-ExcludeNetwork` | Skip network analysis tasks                           | False                       |
| `-ExcludeBrowser` | Skip browser forensics collection                     | False                       |
| `-Quiet`          | Suppress most console output                          | False                       |
| `-Help`           | Display detailed help information                     | False                       |

### Exit Codes

| Code | Meaning                    |
| ---- | -------------------------- |
| 0    | Scan completed successfully |
| 1    | Scan completed with errors  |
| 2    | Prerequisites check failed  |

## Collected Artifacts

| Artifact Category         | Files/Registry Keys                                   | Forensic Value                     |
| ------------------------- | ----------------------------------------------------- | ---------------------------------- |
| **Execution Evidence**    | Amcache.hve, Prefetch/*.pf                            | Program execution history          |
| **User Activity**         | ActivitiesCache.db, UserAssist, RecentDocs, JumpLists | User behavior patterns             |
| **Persistence**           | Run keys, Services, Scheduled Tasks                   | Malware persistence mechanisms     |
| **Network Activity**      | Active connections, Firewall rules, RDP history       | Network communication evidence     |
| **System Activity**       | SRUM database, Event logs                             | System resource usage and events   |
| **Browser Activity**      | Chrome/Edge/Firefox profiles                          | Web browsing history and downloads |
| **Credential Indicators** | LSASS events, SAM/SECURITY copies                     | Credential theft detection         |
| **LOLBAS Activity**       | Process command lines                                 | Living-off-the-land detection      |

## Output Structure

```
WinFire_Results_YYYYMMDD_HHMMSS/
|-- Raw_Data/
|   |-- System_Information.csv/.json
|   |-- Running_Processes.csv/.json
|   |-- LOLBAS_Detection.csv/.json
|   |-- Credential_Indicators.csv/.json
|   |-- Threat_Score.csv/.json
|   |-- Defender_Exclusions.csv/.json
|   |-- PowerShell_History.csv/.json
|   |-- RDP_Analysis.csv/.json
|   |-- Advanced_Process_Analysis.csv/.json
|   |-- JumpList_Analysis.csv/.json
|   +-- LNK_Analysis.csv/.json
|-- Collected_Artifacts/
|   |-- Browser_Profiles/
|   |-- PowerShell_History/
|   |-- JumpLists/
|   |-- Amcache.hve
|   |-- Prefetch/
|   +-- Timeline/
|-- Reports/
|   |-- WinFire_Executive_Summary.html
|   |-- Chain_Of_Custody.json
|   |-- Hash_Manifest.txt
|   +-- Operation_Metrics.csv
|-- WinFire_ExecutionLog.txt
+-- WinFire_Transcript.txt
```

## Examples

### Quick Triage Scan

```powershell
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001" -CaseNumber "INC-2024-001" -Investigator "John Doe"
```

### Comprehensive Investigation

```powershell
.\WinFire.ps1 -Full -OutputPath "D:\Investigations\Malware_Analysis" `
              -CaseNumber "CASE-2024-MAL-005" `
              -Investigator "Jane Smith" `
              -Purpose "Suspected ransomware infection analysis" `
              -HashAlgorithm SHA256
```

### Threat Hunting Focus

```powershell
.\WinFire.ps1 -Full -OutputPath "C:\ThreatHunting" `
              -CaseNumber "HUNT-2024-001" `
              -Purpose "Proactive threat hunting assessment"
# Check Threat_Score.csv for overall risk assessment
```

### Stealth Collection

```powershell
.\WinFire.ps1 -Quick -Quiet -OutputPath "C:\Temp\Scan" -CaseNumber "STEALTH-001"
```

## Legal Considerations

### Authorization Requirements

- **Explicit Authorization**: Ensure you have proper legal authority before running WinFire
- **Scope Limitations**: Only collect data within authorized investigation scope
- **Data Handling**: Follow organizational data protection and privacy policies
- **Chain of Custody**: Maintain proper documentation for legal proceedings

### Compliance Notes

- WinFire generates forensically sound artifacts with integrity verification
- Chain of custody documentation supports legal admissibility
- All collection activities are logged with timestamps
- Hash verification ensures evidence integrity
- Full PowerShell transcript provides audit trail

## Contributing

We welcome contributions to improve WinFire! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Guidelines

- Maintain compatibility with PowerShell 5.1+
- Follow existing naming conventions (`Get-WinFire*`, `Write-WinFireLog`)
- Include comprehensive error handling with `Invoke-WinFireSafeOperation`
- Use `[CmdletBinding()]` on all functions
- Avoid Unicode characters in string literals (ASCII only)
- Use `$script:Version` constant instead of hardcoding version strings

## Roadmap

### Planned Features

- [ ] Memory dump collection for critical processes
- [ ] USN Journal analysis for file system timeline
- [ ] ETW log collection for advanced event tracing
- [ ] Cloud artifact collection (OneDrive, Office 365)
- [ ] API integration with threat intelligence platforms
- [ ] PowerShell 7 Core compatibility

## Support

- **Bug Reports**: [GitHub Issues](https://github.com/Masriyan/WinFire/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Masriyan/WinFire/discussions)
- **Contact**: [sudo3rs@protonmail.com](mailto:sudo3rs@protonmail.com)

## Acknowledgments

- **sudo3rs** - Original author and maintainer

WinFire draws inspiration from established forensic tools: KAPE (Eric Zimmerman), CyLR (Alan Orlikoski), Invoke-LiveResponse (Matt Green), PowerForensics (Jared Atkinson).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security policy and vulnerability reporting, see [SECURITY.md](SECURITY.md).

## Changelog

For detailed version history, see [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

WinFire is intended exclusively for authorized digital forensics, incident response, and cybersecurity investigations. Users are responsible for legal compliance, scope adherence, data protection, and professional use. See [SECURITY.md](SECURITY.md) for full details.

---

**Repository**: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)

_WinFire v2.0.2 - Enterprise-grade forensic artifact collection for Windows_
