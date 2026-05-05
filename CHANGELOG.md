# Changelog

All notable changes to WinFire are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.1] - 2026-05-05

### 🔧 Patch Release - Critical Startup Bug Fixes

This release fixes 5 errors that prevented WinFire from executing properly.

### Fixed

| Bug | Root Cause | Fix |
| --- | ---------- | --- |
| `Author:` not recognized as cmdlet | Pipe `\|` in banner string parsed as PowerShell pipeline operator | Removed pipe character, split into separate `Write-Host` calls |
| `Cannot bind argument to 'Path'` (null) | `Log-WinFireMessage` called before `New-WinFireOutputDirectory` initialized `$script:LogPath` | Added null/existence guard clause before file writes |
| `Privileges` property not found | `WindowsIdentity.Privileges` does not exist in .NET Framework | Replaced with `whoami /priv` output parsing |
| `Test-WinFireAdminPrivileges` not recognized | Function lacked `[CmdletBinding()]` but was called with `-ErrorAction Stop` under strict mode | Added `[CmdletBinding()]` attribute; removed `-ErrorAction Stop` from call site |
| Multiple log write warnings during startup | Admin privilege check ran before output directory existed | Added graceful pre-init fallback for early log writes |

### Changed

| Item | Before | After |
| ---- | ------ | ----- |
| Script size | 2576 lines | 2587 lines |
| Banner format | `Version: 2.0 \| Author: sudo3rs` | `Version: 2.0  Author: sudo3rs` |
| Privilege check | `.Privileges` property (broken) | `whoami /priv` parsing (reliable) |
| Execution order | Banner → Admin check → Directory init | Banner → Admin check (console-only) → Directory init → Log confirmation |

---

## [2.0.0] - 2026-01-29

### 🚀 Major Release - Threat Detection & Enhanced Analysis

This release transforms WinFire from a collection tool into a comprehensive threat detection and forensic analysis platform.

### Added

#### Threat Detection Features

| Feature                       | Description                                                                        |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| **LOLBAS Detection**          | Detect abuse of certutil, mshta, regsvr32, wmic, bitsadmin, and 10+ other binaries |
| **Credential Indicators**     | Detect LSASS access events, credential dumping tools, SAM/SECURITY hive copies     |
| **Advanced Process Analysis** | Identify suspicious parent-child relationships (e.g., Word → PowerShell)           |
| **Threat Scoring**            | Automated 0-100 threat score with Low/Medium/High/Critical risk levels             |

#### New Artifact Collection

| Feature                 | Description                                                      |
| ----------------------- | ---------------------------------------------------------------- |
| **Defender Exclusions** | Collect and flag suspicious Windows Defender exclusions          |
| **PowerShell History**  | Collect PSReadLine command history with threat pattern detection |
| **RDP Analysis**        | Analyze RDP sessions and connection history for lateral movement |
| **Jump List Analysis**  | Collect user activity from Jump Lists                            |
| **LNK File Analysis**   | Parse shortcuts for malicious targets and arguments              |

#### UI/UX Improvements

- 🔥 Enhanced ASCII art banner with animated flame effects
- 🌐 GitHub repository URL display in banner
- 📊 Color-coded output with severity levels

#### Documentation

- 📖 `CONTRIBUTING.md` - Comprehensive contributor guidelines
- 🔒 `SECURITY.md` - Security policy with AV handling guidance
- 📝 `CHANGELOG.md` - Version history (this file)
- ⚠️ "Before You Use" section with AV detection warnings

### Fixed

| Bug                  | Fix                                                               |
| -------------------- | ----------------------------------------------------------------- |
| `Get-CService` typo  | Changed to `Get-Service` with additional Win32_Service collection |
| Extension matching   | Fixed `-in` operator to use `-contains` with proper dot stripping |
| Environment variable | Fixed `$env:ProgramFilesx86` → `${env:ProgramFiles(x86)}` syntax  |
| Service collection   | Now collects both Get-Service and Win32_Service data              |

### Changed

| Item           | Before                | After                 |
| -------------- | --------------------- | --------------------- |
| Script size    | ~1900 lines           | 2576 lines            |
| Function count | 12 forensic functions | 21 forensic functions |
| TotalTasks     | 30                    | 40                    |
| WinFireVersion | 1.0                   | 2.0                   |

### New Output Files

```
Raw_Data/
├── Defender_Exclusions.csv/.json      # NEW
├── PowerShell_History.csv/.json       # NEW
├── RDP_Analysis.csv/.json             # NEW
├── LOLBAS_Detection.csv/.json         # NEW
├── Credential_Indicators.csv/.json    # NEW
├── Advanced_Process_Analysis.csv/.json # NEW
├── Threat_Score.csv/.json             # NEW
├── JumpList_Analysis.csv/.json        # NEW
└── LNK_Analysis.csv/.json             # NEW
```

---

## [1.0.0] - 2024-XX-XX

### 🎉 Initial Release

First public release of WinFire - Windows Forensic Incident Response Engine.

### Added

#### Core Collection Features

- **System Information** - OS, hardware, software inventory
- **User Accounts** - Local users, groups, profile artifacts
- **Process Analysis** - Running processes with command lines and hashes
- **Service Enumeration** - Windows services and startup types
- **Scheduled Tasks** - Task scheduler entries
- **WMI Subscriptions** - WMI event persistence detection

#### Network Forensics

- **Active Connections** - TCP/UDP with owning processes
- **Listening Ports** - All listening services
- **Network Shares** - Local and mapped shares
- **Firewall Rules** - Windows Firewall configuration
- **SMB Sessions** - Open SMB connections

#### File System Artifacts

- **Amcache.hve** - Application execution artifacts
- **Prefetch** - Program execution evidence
- **SRUM Database** - System resource usage
- **Timeline Database** - Windows Timeline data
- **BITS Jobs** - Background transfer service activity

#### Registry Analysis

- **Autorun Keys** - Persistence mechanisms
- **USB History** - Connected USB devices
- **Recent Documents** - MRU lists
- **COM Hijacking** - COM object manipulation
- **Network Drives** - Mapped drive history

#### Event Log Collection

- **Security Log** - Logons, privilege use, account changes
- **System Log** - Service changes, boot/shutdown
- **Application Log** - Crashes, errors
- **PowerShell Log** - Script execution events
- **Defender Log** - Malware detections

#### Browser Forensics

- **Chrome** - Profile data collection
- **Edge** - Profile data collection
- **Firefox** - Profile data collection
- Robust RoboCopy handling for locked files

#### Security Tool Detection

- **Windows Defender** - Status and configuration
- **Third-party AV** - Installed antivirus products
- **EDR/XDR Agents** - Common EDR detection

#### Memory Indicators

- **Loaded DLLs** - Non-system DLL enumeration
- **Process Hollowing** - Suspicious memory indicators
- **DLL Injection** - Injection detection heuristics

#### Reporting

- **HTML Report** - Executive summary with findings
- **Hash Manifest** - SHA256 hashes of all files
- **Chain of Custody** - JSON documentation
- **Evidence Compression** - ZIP archive creation

#### Execution Modes

- **Quick Mode** - Fast, high-impact artifacts
- **Full Mode** - Comprehensive collection
- **ExcludeNetwork** - Skip network analysis
- **ExcludeBrowser** - Skip browser forensics
- **Quiet Mode** - Suppress console output

---

## Version Comparison

| Feature               | v1.0 | v2.0 | v2.0.1 |
| --------------------- | ---- | ---- | ------ |
| Forensic Functions    | 12   | 21   | 21     |
| Threat Detection      | ❌   | ✅   | ✅     |
| LOLBAS Detection      | ❌   | ✅   | ✅     |
| Credential Indicators | ❌   | ✅   | ✅     |
| Threat Scoring        | ❌   | ✅   | ✅     |
| RDP Analysis          | ❌   | ✅   | ✅     |
| Jump Lists            | ❌   | ✅   | ✅     |
| LNK Parsing           | ❌   | ✅   | ✅     |
| Enhanced Banner       | ❌   | ✅   | ✅     |
| AV Warning Docs       | ❌   | ✅   | ✅     |
| Reliable Startup      | ✅   | ❌   | ✅     |
| Privilege Check       | N/A  | ❌   | ✅     |

---

## Roadmap

### Planned for v2.2

- [ ] Memory dump collection for critical processes
- [ ] USN Journal parsing
- [ ] ETW log collection
- [ ] Improved HTML report with charts

### Planned for v3.0

- [ ] Cloud artifact collection (OneDrive, Office 365)
- [ ] API integration with threat intelligence
- [ ] PowerShell 7 Core compatibility
- [ ] Remote collection capabilities

---

**Repository**: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)
