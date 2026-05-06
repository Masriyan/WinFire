# Changelog

All notable changes to WinFire are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project uses semantic versioning.

---

## [2.1.0] - 2026-05-06

### Comprehensive Forensic Expansion and Runtime Hardening

This release adds new collection modules, fixes service/network/admin bugs, improves threat scoring and HTML reporting, and validates the script against a real elevated quick scan.

### Added

| Feature | Output |
| --- | --- |
| Named pipes enumeration with risk classification | `Raw_Data\Named_Pipes.csv/.json` |
| Volume Shadow Copy enumeration | `Raw_Data\Shadow_Copies.csv/.json` |
| Alternate Data Streams scan | `Raw_Data\Alternate_Data_Streams.csv/.json` |
| Proxy, WinHTTP, and WPAD collection | `Raw_Data\Proxy_Settings.csv/.json` |
| Sysmon service/config and event collection | `Raw_Data\Sysmon_Artifacts.csv/.json`, `Sysmon_Events.json` |
| Kernel driver enumeration and signature status | `Raw_Data\Kernel_Drivers.csv/.json` |
| ETW/WMI consumer enumeration | `Raw_Data\ETW_Consumers.csv/.json` |
| AppLocker, WDAC, AMSI, and PowerShell v2 policy state | `Raw_Data\Policy_State.csv/.json` |
| Credential Guard, VBS, BitLocker, TPM, and LSA protection state | `Raw_Data\Security_Posture.csv/.json` |
| Dynamic progress task planning | `Get-WinFirePlannedTaskCount` |
| Enhanced HTML report sections | Executive report module summaries |
| Additional threat scoring indicators | High-risk pipes, VSS, ADS, drivers, LSA, PSv2, Sysmon, WDAC/AppLocker |

### Changed

| Area | Change |
| --- | --- |
| Version metadata | Updated `$script:Version` to `2.1.0` and `$script:BuildDate` to `2026-05-06`. |
| Services output | Replaced legacy `Services.csv/.json` with `Services_Status.csv/.json` and `Services_Detail.csv/.json`. |
| Summary function | Renamed `Get-WinFireSummaryEntry` to `Add-WinFireSummaryEntry`. |
| WMI usage | Replaced remaining `Get-WmiObject` with `Get-CimInstance`. |
| Admin check | `Test-WinFireAdminPrivileges` now returns `$false`; main block handles exit code `3`. |
| Promiscuous mode detection | Removed invalid registry placeholder and uses adapter advanced properties. |
| Threat scoring | Uses raw data for high-signal modules to reduce double counting and false positives. |
| ADS handling | Keeps benign stream names visible while scoring only suspicious ADS entries. |
| Named pipe handling | Keeps low-confidence Chromium and Windows patterns visible while scoring high-risk matches only. |

### Fixed

| Bug | Fix |
| --- | --- |
| Service collection overwrite | Split `Get-Service` and `Get-CimInstance Win32_Service` into separate variables and files. |
| Proxy registry StrictMode failure | Reads optional IE proxy values through safe property lookup. |
| Locked `Amcache.hve` failed operation | Records copy failure as data row instead of failing the safe operation. |
| PowerShell history JSON bloat | Normalizes string values before CSV/JSON serialization. |
| Non-admin abort noise | Admin check no longer emits extra error records before main exit handling. |
| False-positive threat score inflation | Added pipe risk levels and benign ADS stream filtering. |

### Validation

Validated locally with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Help
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Quick -OutputPath .\WinFire_TestRuns -Quiet
```

Latest elevated quick scan:

- Status: `COMPLETED`
- Operations: `1512 total, 1512 succeeded, 0 failed`
- Output: `WinFire_TestRuns\WinFire_Results_20260506_095301`

---

## [2.0.2] - 2026-05-05

### Enterprise-Grade Hardening Release

This release transformed WinFire into a more reliable forensic tool with centralized configuration, phased execution, operation metrics, and comprehensive audit trails.

### Added

| Feature | Description |
| --- | --- |
| Centralized version | `$script:Version` constant replaced hardcoded version strings. |
| Prerequisites validation | `Test-WinFirePrerequisites` checks PowerShell 5.1+ and Windows OS. |
| Professional banner | Shows hostname, user, privilege level, PowerShell version, OS, and start time. |
| Phased execution | Six named phases with clear log markers. |
| Operation metrics | Per-operation timing exported to `Operation_Metrics.csv`. |
| Transcript logging | Full PowerShell transcript to `WinFire_Transcript.txt`. |
| Graceful shutdown | Cancellation flag checked before each safe operation. |
| Execution summary | Final status, duration, operation counts, output path, and report path. |

### Fixed

| Bug | Fix |
| --- | --- |
| `$script:OutputPath` overwrote the `-OutputPath` parameter | Renamed runtime output root to `$script:ResultsPath`. |
| Admin check crash path | Wrapped verification and improved initialization order. |
| Missing output path validation | Added `[ValidateNotNullOrEmpty()]`. |
| Unset `$oldErrorActionPreference` | Moved initialization before the safe-operation `try` block. |
| Unapproved logging verb | Renamed `Log-WinFireMessage` to `Write-WinFireLog`. |
| PowerShell automatic variable conflicts | Renamed local variables such as `$profile` and `$event`. |
| Unicode console artifacts | Replaced banner and output decorations with ASCII-safe text. |

---

## [2.0.1] - 2026-05-05

### Startup Bug Fixes

- Fixed banner parsing issues.
- Guarded logging before log path initialization.
- Replaced invalid `WindowsIdentity.Privileges` usage with `whoami /priv` parsing.
- Added `[CmdletBinding()]` to the admin privilege function.
- Reordered startup so output/logging are initialized predictably.

---

## [2.0.0] - 2026-01-29

### Threat Detection and Enhanced Analysis

### Added

- LOLBAS detection.
- Credential dumping indicators.
- Advanced process parent-child analysis.
- Automated threat scoring.
- Defender exclusions collection.
- PowerShell history collection.
- RDP analysis.
- Jump List analysis.
- LNK file analysis.

### Fixed

- Fixed `Get-CService` typo.
- Fixed suspicious extension matching.
- Fixed `ProgramFiles(x86)` environment variable usage.

---

## [1.0.0] - 2024-XX-XX

### Initial Release

- Core forensic collection for system, users, processes, services, scheduled tasks, and WMI.
- Network forensics for TCP/UDP, firewall, SMB, and shares.
- File system artifacts including Amcache, Prefetch, SRUM, Timeline, and BITS.
- Registry analysis for autoruns, USB, MRU, and COM hijacking.
- Event log collection.
- Browser forensics.
- Security tool detection.
- Memory indicators.
- HTML report, hash manifest, chain of custody, and ZIP packaging.

---

## Version Comparison

| Feature | v1.0 | v2.0 | v2.0.2 | v2.1.0 |
| --- | --- | --- | --- | --- |
| Core forensic collection | Yes | Yes | Yes | Yes |
| Threat detection | No | Yes | Yes | Yes |
| Operation metrics | No | No | Yes | Yes |
| Transcript logging | No | No | Yes | Yes |
| Dynamic progress planning | No | No | No | Yes |
| Named pipes | No | No | No | Yes |
| Shadow copies | No | No | No | Yes |
| ADS scan | No | No | No | Yes |
| Sysmon artifacts | No | No | No | Yes |
| Policy/security posture | No | No | No | Yes |
| Kernel driver signatures | No | No | No | Yes |
| ETW/WMI consumers | No | No | No | Yes |
| Enhanced HTML module sections | No | No | No | Yes |

---

## Roadmap

### Planned for v2.2

- USN Journal parsing.
- Optional critical-process memory dump support.
- More timeline correlation.
- HTML charts and filtering.

### Planned for v3.0

- Cloud artifact collection.
- Threat intelligence enrichment.
- Remote collection workflows.
- Broader PowerShell 7 validation.

---

Repository: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)
