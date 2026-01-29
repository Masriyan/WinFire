# WinFire 🔥

**Windows Forensic Incident Response Engine v2.0**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%2FServer%202016%2B-green.svg)](https://www.microsoft.com/windows)
[![Version](https://img.shields.io/badge/Version-2.0-brightgreen.svg)](https://github.com/Masriyan/WinFire)

> A comprehensive PowerShell tool for Windows digital forensics and incident response, designed to rapidly collect critical forensic artifacts for security investigations.

```
                          )  (      (
                         (   ) )    )\ )
                          ) ( (    (()/(
                         (   ))\    /(_))

  ██╗    ██╗██╗███╗   ██╗███████╗██╗██████╗ ███████╗
  ██║    ██║██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝
  ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║██████╔╝█████╗
  ██║███╗██║██║██║╚██╗██║██╔══╝  ██║██╔══██╗██╔══╝
  ╚███╔███╔╝██║██║ ╚████║██║     ██║██║  ██║███████╗
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝

  Windows Forensic Incident Response Engine v2.0
```

## 📋 Table of Contents

- [⚠️ Before You Use](#️-before-you-use)
- [What's New in v2.0](#-whats-new-in-v20)
- [Overview](#-overview)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Collected Artifacts](#-collected-artifacts)
- [Output Structure](#-output-structure)
- [Examples](#-examples)
- [Legal Considerations](#-legal-considerations)
- [Contributing](#-contributing)
- [Security](#-security)
- [Changelog](#-changelog)
- [License](#-license)

## ⚠️ Before You Use

> [!CAUTION]
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

> [!IMPORTANT]
> **Document any AV exclusions or modifications** in your chain of custody notes for forensic integrity.

## � How WinFire Works

### Execution Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           WINFIRE EXECUTION FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐
    │  START       │
    │  WinFire.ps1 │
    └──────┬───────┘
           │
           ▼
    ┌──────────────────┐     ┌──────────────────┐
    │ Check Admin      │────▶│ Display Warning  │
    │ Privileges       │ No  │ & Exit           │
    └──────┬───────────┘     └──────────────────┘
           │ Yes
           ▼
    ┌──────────────────┐
    │ Show Banner      │
    │ Initialize Logs  │
    │ Create Folders   │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐
    │ Chain of Custody │
    │ Documentation    │
    └──────┬───────────┘
           │
           ▼
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                        FORENSIC COLLECTION PHASE                         ║
    ╟──────────────────────────────────────────────────────────────────────────╢
    ║                                                                          ║
    ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     ║
    ║  │   System    │  │    User     │  │  Process &  │  │  Network    │     ║
    ║  │    Info     │  │  Accounts   │  │  Services   │  │  Analysis   │     ║
    ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     ║
    ║                                                                          ║
    ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     ║
    ║  │ File System │  │  Registry   │  │ Event Logs  │  │  Browser    │     ║
    ║  │  Artifacts  │  │  Analysis   │  │ Collection  │  │  Forensics  │     ║
    ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     ║
    ║                                                                          ║
    ╚══════════════════════════════════════════════════════════════════════════╝
           │
           ▼
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                     THREAT DETECTION PHASE (v2.0+)                       ║
    ╟──────────────────────────────────────────────────────────────────────────╢
    ║                                                                          ║
    ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     ║
    ║  │   LOLBAS    │  │ Credential  │  │  Advanced   │  │   Threat    │     ║
    ║  │ Detection   │  │ Indicators  │  │  Process    │  │   Score     │     ║
    ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     ║
    ║                                                                          ║
    ║  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     ║
    ║  │  Defender   │  │ PowerShell  │  │    RDP      │  │ Jump List & │     ║
    ║  │ Exclusions  │  │   History   │  │  Analysis   │  │ LNK Files   │     ║
    ║  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     ║
    ║                                                                          ║
    ╚══════════════════════════════════════════════════════════════════════════╝
           │
           ▼
    ┌──────────────────┐
    │ Generate Reports │
    │ • HTML Summary   │
    │ • Hash Manifest  │
    │ • Compress ZIP   │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────┐
    │     END      │
    │  Complete!   │
    └──────────────┘


    ┌─────────────────────────────────────────────────────────────────────────┐
    │                         OUTPUT STRUCTURE                                │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                                                                         │
    │   WinFire_Results_20260129_103045/                                      │
    │   ├── 📁 Raw_Data/                 ← CSV & JSON files                   │
    │   │   ├── System_Information.csv                                        │
    │   │   ├── Running_Processes.csv                                         │
    │   │   ├── LOLBAS_Detection.csv     ← NEW v2.0                           │
    │   │   ├── Threat_Score.csv         ← NEW v2.0                           │
    │   │   └── ... (30+ files)                                               │
    │   │                                                                     │
    │   ├── 📁 Collected_Artifacts/      ← Binary artifacts                   │
    │   │   ├── Amcache.hve                                                   │
    │   │   ├── Prefetch/                                                     │
    │   │   ├── Browser_Profiles/                                             │
    │   │   └── PowerShell_History/      ← NEW v2.0                           │
    │   │                                                                     │
    │   ├── 📁 Reports/                  ← Analysis reports                   │
    │   │   ├── WinFire_Executive_Summary.html                                │
    │   │   ├── Chain_Of_Custody.json                                         │
    │   │   └── Hash_Manifest.txt                                             │
    │   │                                                                     │
    │   └── 📄 WinFire_ExecutionLog.txt  ← Detailed log                       │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

### Sample Report Output

Below is an example of what the **Threat Score** output looks like:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      SAMPLE: Threat_Score.csv                          │
├────────────────┬────────────┬───────────────┬──────────────────────────┤
│ ThreatScore    │ RiskLevel  │ TotalFindings │ CalculatedAt             │
├────────────────┼────────────┼───────────────┼──────────────────────────┤
│ 35             │ High       │ 7             │ 2026-01-29 10:30:45      │
└────────────────┴────────────┴───────────────┴──────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    SAMPLE: LOLBAS_Detection.csv                        │
├─────────────┬──────┬─────────────────────────────────┬─────────────────┤
│ ProcessName │ PID  │ CommandLine                     │ Severity        │
├─────────────┼──────┼─────────────────────────────────┼─────────────────┤
│ certutil    │ 4521 │ certutil -urlcache -f http://...│ High            │
│ mshta       │ 3842 │ mshta vbscript:Execute(...)     │ High            │
└─────────────┴──────┴─────────────────────────────────┴─────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│              SAMPLE: Credential_Indicators.csv                         │
├────────────────────┬──────────┬─────────────────────────┬──────────────┤
│ Type               │ EventId  │ Details                 │ Severity     │
├────────────────────┼──────────┼─────────────────────────┼──────────────┤
│ LSASS Access Event │ 4656     │ Potential cred dumping  │ Critical     │
│ Registry Hive Copy │ N/A      │ SAM found in Downloads  │ Critical     │
└────────────────────┴──────────┴─────────────────────────┴──────────────┘
```

### Risk Level Guide

| Score  | Level           | Action Required                              |
| ------ | --------------- | -------------------------------------------- |
| 0-10   | 🟢 **Low**      | Routine findings, standard review            |
| 11-30  | 🟡 **Medium**   | Notable findings, investigate warnings       |
| 31-60  | 🟠 **High**     | Significant threats, prioritize analysis     |
| 61-100 | 🔴 **Critical** | Active compromise likely, immediate response |

## �🚀 What's New in v2.0

### Major New Features

| Feature                          | Description                                                                       |
| -------------------------------- | --------------------------------------------------------------------------------- |
| 🔍 **LOLBAS Detection**          | Detect Living-Off-The-Land Binary abuse (certutil, mshta, regsvr32, wmic, etc.)   |
| 🔑 **Credential Indicators**     | Identify LSASS access, credential dumping tools, and SAM/SECURITY hive copies     |
| 🛡️ **Defender Exclusions**       | Collect and flag suspicious Windows Defender exclusions                           |
| 📜 **PowerShell History**        | Collect PSReadLine command history with suspicious pattern detection              |
| 🖥️ **RDP Analysis**              | Analyze RDP sessions and connection history for lateral movement                  |
| 🔄 **Advanced Process Analysis** | Detect suspicious parent-child relationships and processes from unusual locations |
| 📊 **Threat Scoring**            | Automated system threat score (0-100) with risk level assessment                  |
| 📁 **Jump List Analysis**        | Collect and analyze user activity from Jump Lists                                 |
| 🔗 **LNK File Analysis**         | Parse shortcuts for suspicious targets and arguments                              |

### Bug Fixes

- Fixed `Get-CService` typo (was causing service collection failures)
- Fixed extension matching for suspicious file detection
- Fixed `ProgramFiles(x86)` environment variable syntax
- Improved service collection with both Get-Service and Win32_Service

### UI Improvements

- Enhanced ASCII art banner with animated flame effects
- Added GitHub repository URL display
- Improved version display and formatting

## 🎯 Overview

WinFire is an all-in-one PowerShell script designed for incident responders, digital forensics investigators, and cybersecurity professionals. It rapidly collects critical forensic artifacts from Windows systems, providing structured output in multiple formats (CSV, JSON, HTML) for immediate analysis or integration with other forensic tools.

### Key Capabilities

- **Rapid Artifact Collection**: Efficiently gathers evidence from running systems
- **Threat Detection**: Active threat hunting with LOLBAS, credential, and process analysis
- **Automated Scoring**: System-wide threat assessment with risk levels
- **Chain of Custody**: Maintains forensic integrity with proper documentation
- **Multi-Format Output**: CSV, JSON, and HTML reports for various analysis workflows
- **Evidence Integrity**: Cryptographic hashing ensures artifact authenticity

## ✨ Features

### 🔍 **Threat Detection (NEW in v2.0)**

- LOLBAS (Living-Off-The-Land Binary) abuse detection
- Credential harvesting/dumping indicators
- Suspicious process parent-child relationships
- Windows Defender exclusion analysis
- PowerShell command history with threat patterns
- RDP lateral movement detection
- Automated threat scoring (0-100)

### 📊 **System Analysis**

- Operating system and hardware information
- Installed software inventory
- Environment variables and system paths
- Network configuration and interfaces

### 👥 **User Activity Tracking**

- Local user accounts and group memberships
- User profile artifacts and recent file access
- Registry-based user activity (UserAssist, ShellBags)
- Windows Timeline database collection
- Jump List analysis (NEW)
- LNK file parsing (NEW)

### 🔄 **Process & Service Analysis**

- Running processes with command lines and hashes
- Windows services and startup configurations
- Scheduled tasks enumeration
- WMI event subscriptions (persistence mechanism)
- Advanced process tree analysis (NEW)

### 🌐 **Network Forensics**

- Active network connections (TCP/UDP)
- Listening ports and associated processes
- Network shares and mapped drives
- Windows Firewall rules
- SMB sessions and open files
- RDP connection history (NEW)

### 📁 **File System Artifacts**

- Recently modified files in critical locations
- Suspicious file detection based on extensions/attributes
- Startup folder contents
- **Amcache.hve** - Application execution artifacts
- **Prefetch files** - Program execution evidence
- **SRUM database** - System resource usage monitoring
- **BITS jobs** - Background transfer service activity

### 🔧 **Registry Analysis**

- Autorun/persistence registry keys
- USB device history
- Recent documents and MRU lists
- COM hijacking indicators
- Network drive history

### 📊 **Event Log Collection**

- Security events (logons, privilege use, account changes)
- System events (service changes, boot/shutdown)
- Application crash events
- PowerShell operational logs
- Windows Defender detection events

### 🌐 **Browser Forensics**

- Chrome, Edge, and Firefox profile collection
- Robust handling of locked browser files using RoboCopy
- Cache and history databases for offline analysis

### 🛡️ **Security Tool Detection**

- Windows Defender status and configuration
- Defender exclusion analysis (NEW)
- Installed antivirus products detection
- EDR/XDR agent identification
- PowerShell logging configuration analysis

### 🧠 **Memory Analysis Indicators**

- Loaded DLL enumeration
- Process hollowing indicators
- DLL injection detection
- Suspicious process identification

## 📋 Prerequisites

### System Requirements

- **Operating System**: Windows 10, Windows 11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Disk Space**: Minimum 1GB free space (varies by system activity)

### Recommended Privileges

WinFire automatically checks for and benefits from these privileges:

- `SeDebugPrivilege` - Access to all processes
- `SeBackupPrivilege` - Read access to all files
- `SeRestorePrivilege` - Restore file attributes

## 🚀 Installation

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

You may need to adjust PowerShell execution policy:

```powershell
# Temporarily allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Or sign the script with your code signing certificate
# Set-AuthenticodeSignature -FilePath "WinFire.ps1" -Certificate $cert
```

## 🎮 Usage

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

## 📦 Collected Artifacts

### Critical Windows Forensic Artifacts

| Artifact Category         | Files/Registry Keys                                   | Forensic Value                     |
| ------------------------- | ----------------------------------------------------- | ---------------------------------- |
| **Execution Evidence**    | Amcache.hve, Prefetch/\*.pf                           | Program execution history          |
| **User Activity**         | ActivitiesCache.db, UserAssist, RecentDocs, JumpLists | User behavior patterns             |
| **Persistence**           | Run keys, Services, Scheduled Tasks                   | Malware persistence mechanisms     |
| **Network Activity**      | Active connections, Firewall rules, RDP history       | Network communication evidence     |
| **System Activity**       | SRUM database, Event logs                             | System resource usage and events   |
| **Browser Activity**      | Chrome/Edge/Firefox profiles                          | Web browsing history and downloads |
| **Credential Indicators** | LSASS events, SAM/SECURITY copies                     | Credential theft detection         |
| **LOLBAS Activity**       | Process command lines                                 | Living-off-the-land detection      |

### New v2.0 Output Files

| File                                  | Description                               |
| ------------------------------------- | ----------------------------------------- |
| `Defender_Exclusions.csv/.json`       | Windows Defender exclusion analysis       |
| `PowerShell_History.csv/.json`        | User PowerShell command history           |
| `RDP_Analysis.csv/.json`              | RDP connections and session data          |
| `LOLBAS_Detection.csv/.json`          | Living-off-the-land binary abuse findings |
| `Credential_Indicators.csv/.json`     | Credential harvesting/dumping indicators  |
| `Advanced_Process_Analysis.csv/.json` | Suspicious process relationships          |
| `Threat_Score.csv/.json`              | Overall system threat assessment          |
| `JumpList_Analysis.csv/.json`         | User activity from jump lists             |
| `LNK_Analysis.csv/.json`              | Shortcut file analysis                    |

## 📂 Output Structure

After execution, WinFire creates a timestamped directory:

```
WinFire_Results_YYYYMMDD_HHMMSS/
├── Raw_Data/                          # Structured data files
│   ├── System_Information.csv/.json
│   ├── Running_Processes.csv/.json
│   ├── LOLBAS_Detection.csv/.json          # NEW
│   ├── Credential_Indicators.csv/.json     # NEW
│   ├── Threat_Score.csv/.json              # NEW
│   └── [Additional CSV/JSON files...]
├── Collected_Artifacts/               # Binary artifacts
│   ├── Browser_Profiles/
│   ├── PowerShell_History/                 # NEW
│   ├── JumpLists/                          # NEW
│   ├── Amcache.hve
│   ├── Prefetch/
│   └── Timeline/
├── Reports/
│   ├── WinFire_Executive_Summary.html
│   ├── Chain_Of_Custody.json
│   └── Hash_Manifest.txt
└── WinFire_ExecutionLog.txt
```

## 💡 Examples

### Quick Triage Scan

```powershell
# Rapid scan for immediate threat assessment
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001" -CaseNumber "INC-2024-001" -Investigator "John Doe"
```

### Comprehensive Investigation

```powershell
# Full forensic collection with case documentation
.\WinFire.ps1 -Full -OutputPath "D:\Investigations\Malware_Analysis" `
              -CaseNumber "CASE-2024-MAL-005" `
              -Investigator "Jane Smith" `
              -Purpose "Suspected ransomware infection analysis" `
              -HashAlgorithm SHA256
```

### Threat Hunting Focus

```powershell
# Full scan with focus on reviewing threat score
.\WinFire.ps1 -Full -OutputPath "C:\ThreatHunting" `
              -CaseNumber "HUNT-2024-001" `
              -Purpose "Proactive threat hunting assessment"
# Check Threat_Score.csv for overall risk assessment
```

### Stealth Collection

```powershell
# Minimal console output for covert collection
.\WinFire.ps1 -Quick -Quiet -OutputPath "C:\Temp\Scan" -CaseNumber "STEALTH-001"
```

## ⚖️ Legal Considerations

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

## 🤝 Contributing

We welcome contributions to improve WinFire! Here's how you can help:

### Reporting Issues

1. Check existing [issues](https://github.com/Masriyan/WinFire/issues) first
2. Provide detailed description of the problem
3. Include system information and error messages
4. Specify WinFire version and PowerShell version

### Feature Requests

1. Open an [issue](https://github.com/Masriyan/WinFire/issues/new) with the enhancement label
2. Describe the forensic value of the proposed feature
3. Provide use case examples

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-artifact`)
3. Follow existing code style and patterns
4. Add appropriate error handling with `Invoke-WinFireSafeOperation`
5. Test thoroughly on different Windows versions
6. Update documentation as needed
7. Open a Pull Request

### Development Guidelines

- Maintain compatibility with PowerShell 5.1+
- Follow existing naming conventions (`Get-WinFire*`)
- Include comprehensive error handling
- Add appropriate logging with `Log-WinFireMessage`

## 📈 Roadmap

### Planned Features

- [ ] **Memory dump collection** for critical processes
- [ ] **USN Journal analysis** for file system timeline
- [ ] **ETW log collection** for advanced event tracing
- [ ] **Cloud artifact collection** (OneDrive, Office 365)
- [ ] **API integration** with threat intelligence platforms
- [ ] **PowerShell 7 Core** compatibility

### Version History

- **v2.0** - Major update with 10 new threat detection features, bug fixes, and UI improvements
- **v1.0** - Initial release with core forensic collection capabilities

## 📞 Support

### Community Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Masriyan/WinFire/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Masriyan/WinFire/discussions)
- 📧 **Contact**: [sudo3rs@protonmail.com](mailto:sudo3rs@protonmail.com)

## 🏆 Acknowledgments

### Contributors

- **sudo3rs** - Original author and maintainer

### Inspiration

WinFire draws inspiration from established forensic tools:

- **KAPE** by Eric Zimmerman
- **CyLR** by Alan Orlikoski
- **Invoke-LiveResponse** by Matt Green
- **PowerForensics** by Jared Atkinson

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024-2026 sudo3rs

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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## 🔒 Security

For security policy, vulnerability reporting, and important notices about antivirus detection, please see [SECURITY.md](SECURITY.md).

## 📝 Changelog

For detailed version history and changes, please see [CHANGELOG.md](CHANGELOG.md).

## ⚠️ Disclaimer

**IMPORTANT**: WinFire is designed for legitimate digital forensics, incident response, and cybersecurity investigations. Users are responsible for:

- **Legal Compliance**: Ensuring proper authorization before system analysis
- **Scope Adherence**: Operating within authorized investigation boundaries
- **Data Protection**: Following applicable privacy and data protection laws
- **Professional Use**: Using the tool only for lawful security purposes

### Technical Limitations

- Requires **Administrator privileges** for complete artifact collection
- Some artifacts may be **inaccessible** due to system protections
- **Anti-malware software** may flag or block certain collection activities
- Results should be **validated** with additional forensic tools

---

**🔥 Happy Hunting! 🔥**

_WinFire v2.0 - Illuminating the path to digital truth_
