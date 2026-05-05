# Changelog

All notable changes to WinFire are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.2] - 2026-05-05

### Enterprise-Grade Hardening Release

This release transforms WinFire into an enterprise-grade forensic tool with centralized
configuration, phased execution, operation metrics, and comprehensive audit trails.

### Added

| Feature                      | Description                                                             |
| ---------------------------- | ----------------------------------------------------------------------- |
| **Centralized Version**      | `$script:Version` constant replaces all hardcoded version strings       |
| **Prerequisites Validation** | `Test-WinFirePrerequisites` checks PS >= 5.1 and Windows OS at startup  |
| **Professional Banner**      | Shows hostname, user, privilege level, PS version, OS, start time       |
| **Phased Execution**         | 6 named phases with clear log markers                                   |
| **Operation Metrics**        | Per-operation `Stopwatch` timing, exported to `Operation_Metrics.csv`   |
| **Transcript Logging**       | Full PowerShell transcript to `WinFire_Transcript.txt`                  |
| **Graceful Shutdown**        | `$script:CancelRequested` flag checked before each operation            |
| **Exit Codes**               | `0` success, `1` error, `2` prerequisites failed                       |
| **Execution Summary**        | Professional summary with status, duration, operation counts            |

### Fixed

| Bug | Root Cause | Fix |
| --- | ---------- | --- |
| `Join-Path` empty 'Path' errors | `$script:OutputPath = $null` overwrites `$OutputPath` parameter | Renamed to `$script:ResultsPath` |
| `Test-WinFireAdminPrivileges` crash | Unhandled exception cascades | Wrapped in `try/catch` |
| `New-WinFireOutputDirectory` empty path | No parameter validation | Added `[ValidateNotNullOrEmpty()]` |
| `$oldErrorActionPreference` unset | Declared inside `try{}`, used in `finally{}` | Moved before `try` block |
| `Log-WinFireMessage` unapproved verb | PSScriptAnalyzer warning | Renamed to `Write-WinFireLog` |
| `$profile` automatic variable conflict | Shadows PowerShell's `$PROFILE` | Renamed to `$userProfile` |
| `$event` automatic variable conflict | Shadows PowerShell's `$Event` | Renamed to `$logEvent` |
| `$null` on wrong side of comparison | PSScriptAnalyzer warning | Flipped to `$null -eq $var` |
| `$dnsEntries` assigned but unused | Dead code | Removed |
| `$persistenceKeys` assigned but unused | Dead code | Removed |
| `$hash` assigned but unused | Unused Get-FileHashSafe call | Removed |
| Unicode parse errors on PS 5.1 | Box-drawing characters in string literals | Replaced with ASCII |

### Changed

| Item | Before | After |
| ---- | ------ | ----- |
| Script lines | 2599 | 2686 |
| Function count | 33 | 34 (+Test-WinFirePrerequisites) |
| Internal results variable | `$script:OutputPath` | `$script:ResultsPath` |
| Log function name | `Log-WinFireMessage` | `Write-WinFireLog` |
| Banner | ASCII art + Unicode box | Clean text with system context |
| Execution flow | Flat function list | 6 phased scan pipeline |
| Error output | Generic completion message | Structured execution summary |
| File encoding | Mixed | UTF-8 with BOM (ASCII-only content) |

### New Output Files

```
Reports/
+-- Operation_Metrics.csv       # Per-operation timing and status

WinFire_Transcript.txt          # Full PowerShell transcript
```

---

## [2.0.1] - 2026-05-05

### Patch Release - Startup Bug Fixes

This release fixes 5 errors that prevented WinFire from executing properly.

### Fixed

| Bug | Root Cause | Fix |
| --- | ---------- | --- |
| `Author:` not recognized as cmdlet | Pipe `\|` in banner string parsed as pipeline operator | Removed pipe character |
| `Cannot bind argument to 'Path'` (null) | `Log-WinFireMessage` called before `$script:LogPath` initialized | Added null guard clause |
| `Privileges` property not found | `WindowsIdentity.Privileges` does not exist in .NET | Replaced with `whoami /priv` parsing |
| `Test-WinFireAdminPrivileges` not recognized | Function lacked `[CmdletBinding()]` | Added attribute |
| Multiple log write warnings | Admin check ran before output directory existed | Reordered execution |

---

## [2.0.0] - 2026-01-29

### Major Release - Threat Detection & Enhanced Analysis

### Added

#### Threat Detection Features

| Feature                       | Description                                                                        |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| **LOLBAS Detection**          | Detect abuse of certutil, mshta, regsvr32, wmic, bitsadmin, and 10+ other binaries |
| **Credential Indicators**     | Detect LSASS access events, credential dumping tools, SAM/SECURITY hive copies     |
| **Advanced Process Analysis** | Identify suspicious parent-child relationships (e.g., Word -> PowerShell)          |
| **Threat Scoring**            | Automated 0-100 threat score with Low/Medium/High/Critical risk levels             |

#### New Artifact Collection

| Feature                 | Description                                                      |
| ----------------------- | ---------------------------------------------------------------- |
| **Defender Exclusions** | Collect and flag suspicious Windows Defender exclusions          |
| **PowerShell History**  | Collect PSReadLine command history with threat pattern detection |
| **RDP Analysis**        | Analyze RDP sessions and connection history for lateral movement |
| **Jump List Analysis**  | Collect user activity from Jump Lists                            |
| **LNK File Analysis**   | Parse shortcuts for malicious targets and arguments              |

### Fixed

| Bug                  | Fix                                                               |
| -------------------- | ----------------------------------------------------------------- |
| `Get-CService` typo  | Changed to `Get-Service` with additional Win32_Service collection |
| Extension matching   | Fixed `-in` operator to use `-contains` with proper dot stripping |
| Environment variable | Fixed `$env:ProgramFilesx86` syntax                               |

---

## [1.0.0] - 2024-XX-XX

### Initial Release

First public release of WinFire - Windows Forensic Incident Response Engine.

- Core forensic collection: System, Users, Processes, Services, Scheduled Tasks, WMI
- Network forensics: TCP/UDP, Firewall, SMB, Shares
- File system artifacts: Amcache, Prefetch, SRUM, Timeline, BITS
- Registry analysis: Autoruns, USB, MRU, COM Hijacking
- Event log collection: Security, System, Application, PowerShell, Defender
- Browser forensics: Chrome, Edge, Firefox with RoboCopy
- Security tool detection: Defender, AV, EDR
- Memory indicators: DLLs, hollowing, injection
- Reporting: HTML, Hash Manifest, Chain of Custody, ZIP

---

## Version Comparison

| Feature               | v1.0 | v2.0 | v2.0.1 | v2.0.2 |
| --------------------- | ---- | ---- | ------ | ------ |
| Forensic Functions    | 12   | 21   | 21     | 21     |
| Threat Detection      | -    | Yes  | Yes    | Yes    |
| LOLBAS Detection      | -    | Yes  | Yes    | Yes    |
| Credential Indicators | -    | Yes  | Yes    | Yes    |
| Threat Scoring        | -    | Yes  | Yes    | Yes    |
| Reliable Startup      | Yes  | No   | No     | Yes    |
| StrictMode Safe       | N/A  | No   | No     | Yes    |
| Prerequisites Check   | -    | -    | -      | Yes    |
| Operation Metrics     | -    | -    | -      | Yes    |
| Transcript Logging    | -    | -    | -      | Yes    |
| Phased Execution      | -    | -    | -      | Yes    |
| Exit Codes            | -    | -    | -      | Yes    |
| Graceful Shutdown     | -    | -    | -      | Yes    |

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
