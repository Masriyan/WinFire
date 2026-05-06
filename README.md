# WinFire

**Windows Forensic Incident Response Engine v2.1.0**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%2FServer%202016%2B-green.svg)](https://www.microsoft.com/windows)
[![Version](https://img.shields.io/badge/Version-2.1.0-brightgreen.svg)](https://github.com/Masriyan/WinFire)

WinFire is a PowerShell-based Windows forensic incident response engine. It collects live-response artifacts from Windows systems, exports structured CSV/JSON data, generates an executive HTML report, records chain-of-custody metadata, and packages evidence for review.

## Table of Contents

- [Before You Use](#before-you-use)
- [What Is New in v2.1.0](#what-is-new-in-v210)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Threat Scoring](#threat-scoring)
- [Validation Status](#validation-status)
- [Legal Notice](#legal-notice)
- [Contributing](#contributing)
- [Security](#security)

## Before You Use

WinFire performs legitimate forensic activity that can look similar to attacker reconnaissance or data collection. Antivirus and EDR tools may alert on or block the script.

Recommended handling:

1. Get written authorization before collection.
2. Coordinate with the SOC or security operations owner.
3. Document any AV/EDR exclusions in chain-of-custody notes.
4. Run PowerShell as Administrator.
5. Store results on protected forensic storage.

Example Defender exclusion:

```powershell
Add-MpPreference -ExclusionPath "C:\Tools\WinFire"
```

## What Is New in v2.1.0

v2.1.0 adds new forensic modules, fixes collection bugs, improves report coverage, and hardens runtime behavior.

### New Collection Modules

| Module | Output |
| --- | --- |
| Named pipes enumeration with risk classification | `Raw_Data\Named_Pipes.csv/.json` |
| Volume Shadow Copy enumeration | `Raw_Data\Shadow_Copies.csv/.json` |
| Alternate Data Streams scan | `Raw_Data\Alternate_Data_Streams.csv/.json` |
| Proxy, WPAD, and WinHTTP settings | `Raw_Data\Proxy_Settings.csv/.json` |
| Sysmon service/config/event collection | `Raw_Data\Sysmon_Artifacts.csv/.json`, `Sysmon_Events.json` |
| Kernel driver enumeration and signing status | `Raw_Data\Kernel_Drivers.csv/.json` |
| ETW/WMI consumer enumeration | `Raw_Data\ETW_Consumers.csv/.json` |
| AppLocker, WDAC, AMSI, PowerShell v2 state | `Raw_Data\Policy_State.csv/.json` |
| Credential Guard, VBS, BitLocker, TPM, LSA protection | `Raw_Data\Security_Posture.csv/.json` |

### Notable Fixes

- Split service collection into `Services_Status` from `Get-Service` and `Services_Detail` from `Get-CimInstance Win32_Service`.
- Replaced remaining `Get-WmiObject` usage with `Get-CimInstance`.
- Replaced `Get-WinFireSummaryEntry` with approved verb `Add-WinFireSummaryEntry`.
- Changed admin privilege check to return `$false`; main execution handles exit and logging.
- Added dynamic progress task calculation with `Get-WinFirePlannedTaskCount`.
- Fixed proxy registry collection under StrictMode when optional registry values do not exist.
- Changed locked `Amcache.hve` handling so lock failures are recorded as data rows instead of failed operations.
- Fixed JSON serialization bloat for PowerShell history strings.
- Tuned named-pipe and ADS false positives by adding risk classification.

## Features

### System Baseline

- OS, BIOS, CPU, timezone, network configuration, DNS cache, ARP, routes.
- Installed software inventory.
- Environment variables and system paths.
- Local users, groups, group membership, and selected profile artifacts.

### Process and Service Analysis

- Running processes, parent PID, command line, executable path, owner, and hashes.
- Service status and detailed service configuration.
- Scheduled tasks.
- WMI event subscriptions.
- ETW/WMI consumer classes.
- Kernel drivers with signature status.

### Network Analysis

- TCP and UDP connections.
- Listening ports.
- Network shares and mapped drives.
- Firewall rules.
- Proxy, WinHTTP, and WPAD state.
- Promiscuous-mode adapter property checks.
- SMB sessions and open files.
- Network profiles.
- Named pipes with pattern and risk classification.

### File System and Registry

- Recent files in high-risk locations.
- Suspicious file extension/name/attribute checks.
- Startup folder items.
- Amcache, Prefetch, SRUM, Windows Timeline, and BITS jobs.
- Volume Shadow Copy inventory.
- Alternate Data Streams scan with benign stream filtering.
- Autorun registry keys, USB history, RecentDocs, UserAssist, ShellBags, network drive history, and COM hijacking indicators.

### Event Logs and Browser Forensics

- Security, System, Application, PowerShell, and Defender event logs.
- Sysmon service and event data when installed.
- Chrome, Edge, and Firefox high-value browser artifacts.
- Locked browser files are reported instead of crashing the scan.

### Advanced Threat Detection

- Windows Defender status and exclusions.
- AV and EDR service detection.
- Loaded modules, DLL injection indicators, and process hollowing indicators.
- PowerShell logging configuration.
- PowerShell history threat patterns.
- RDP activity.
- LOLBAS abuse patterns.
- Credential dumping indicators.
- Advanced parent-child process analysis.
- Jump List and LNK analysis.
- Threat score with risk level.

## Requirements

| Requirement | Value |
| --- | --- |
| Operating system | Windows 10, Windows 11, Windows Server 2016+ |
| PowerShell | Windows PowerShell 5.1+ |
| Privileges | Administrator required |
| Recommended privileges | `SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege` |
| Disk space | Depends on system activity; 1 GB+ recommended |

## Usage

Run from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001" -CaseNumber "INC-001" -Investigator "Analyst"
```

Full collection:

```powershell
.\WinFire.ps1 -Full -OutputPath "D:\Cases\Case001" `
    -CaseNumber "CASE-001" `
    -Investigator "Analyst" `
    -Purpose "Suspected ransomware intrusion"
```

Quiet quick scan:

```powershell
.\WinFire.ps1 -Quick -Quiet -OutputPath "C:\Forensics\Quick"
```

Exclude selected modules:

```powershell
.\WinFire.ps1 -Quick -ExcludeNetwork -ExcludeBrowser -OutputPath "C:\Forensics\Scoped"
```

### Parameters

| Parameter | Description |
| --- | --- |
| `-Quick` | Faster scan focused on high-impact artifacts. |
| `-Full` | Comprehensive scan. Used by default when neither `-Quick` nor `-Full` is specified. |
| `-OutputPath` | Base directory where timestamped results are created. |
| `-ExcludeNetwork` | Skip network and named pipe analysis. |
| `-ExcludeBrowser` | Skip browser artifact collection. |
| `-HashAlgorithm` | `MD5`, `SHA1`, or `SHA256`. Default is `SHA256`. |
| `-Quiet` | Reduce console output. Warnings and final summary still appear. |
| `-CaseNumber` | Case identifier for chain of custody. |
| `-Investigator` | Investigator name for chain of custody. |
| `-Purpose` | Purpose text for chain of custody. |
| `-Help` | Show help. |

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Completed successfully. |
| `1` | Critical scan error. |
| `2` | Prerequisite check failed. |
| `3` | Administrator privileges missing or could not be verified. |

## Output Structure

```text
WinFire_Results_YYYYMMDD_HHMMSS/
|-- Raw_Data/
|   |-- System_Information.csv/.json
|   |-- User_Accounts.csv/.json
|   |-- Running_Processes.csv/.json
|   |-- Services_Status.csv/.json
|   |-- Services_Detail.csv/.json
|   |-- Scheduled_Tasks.csv/.json
|   |-- WMI_Event_Subscriptions.csv/.json
|   |-- ETW_Consumers.csv/.json
|   |-- Kernel_Drivers.csv/.json
|   |-- Active_Network_Connections.csv/.json
|   |-- Listening_Ports.csv/.json
|   |-- Firewall_Rules.csv/.json
|   |-- Proxy_Settings.csv/.json
|   |-- Named_Pipes.csv/.json
|   |-- Shadow_Copies.csv/.json
|   |-- Alternate_Data_Streams.csv/.json
|   |-- Policy_State.csv/.json
|   |-- Security_Posture.csv/.json
|   |-- Sysmon_Artifacts.csv/.json
|   |-- Sysmon_Events.json
|   |-- Threat_Score.csv/.json
|   +-- ...
|-- Collected_Artifacts/
|   |-- Browser_Profiles/
|   |-- JumpLists/
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

## Threat Scoring

WinFire calculates a score from summary warnings and high-signal raw indicators. v2.1.0 adds scoring for:

- High-risk named pipe matches.
- Missing VSS shadow copies.
- Suspicious Alternate Data Streams.
- Unsigned running kernel drivers.
- LSA RunAsPPL disabled.
- PowerShell v2 downgrade risk.
- Sysmon missing.
- WDAC/AppLocker missing or unavailable.

Risk levels:

| Score | Level |
| --- | --- |
| 0-10 | Low |
| 11-30 | Medium |
| 31-60 | High |
| 61-100 | Critical |

Treat the score as triage guidance, not as a final compromise verdict.

## Validation Status

The current script was validated on Windows PowerShell 5.1 with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Help
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Quick -OutputPath .\WinFire_TestRuns -Quiet
```

Latest local quick scan result:

- Status: `COMPLETED`
- Operations: `1512 total, 1512 succeeded, 0 failed`
- Output: `WinFire_TestRuns\WinFire_Results_20260506_095301`

Expected live-system warnings include locked temp/browser files, missing optional forensic privileges, missing Sysmon, or no VSS snapshots.

## Legal Notice

WinFire is intended only for authorized digital forensics, incident response, security assessment, and system administration. Users are responsible for authorization, legal compliance, data protection, and chain-of-custody documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

---

Repository: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)

WinFire v2.1.0 - Windows forensic incident response collection for authorized investigations.
