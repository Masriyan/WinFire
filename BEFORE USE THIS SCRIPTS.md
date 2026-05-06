# Before You Use WinFire

This document explains what to confirm before running WinFire, why security tools may alert on it, and how to review results safely.

## Summary

WinFire is a live-response forensic collection script. It is intended for authorized Windows digital forensics and incident response.

Because it collects sensitive artifacts, it can look similar to attacker reconnaissance or information theft when observed by AV/EDR tools. Detection is expected. Coordinate before use and document all security-tool changes.

## Minimum Checklist

Before running:

- Confirm written authorization.
- Confirm the target system is in scope.
- Open PowerShell as Administrator.
- Verify the script source and hash if you received it from a release package.
- Prepare a secure output location.
- Notify the SOC or security tooling owner.
- Record case number, investigator, purpose, date, and time.

After running:

- Review `WinFire_ExecutionLog.txt`.
- Review `Reports\Operation_Metrics.csv`.
- Review `Raw_Data\Threat_Score.csv`.
- Preserve `Reports\Hash_Manifest.txt`.
- Store the result ZIP and folder securely.
- Remove temporary AV/EDR exclusions.
- Complete chain-of-custody notes.

## Recommended Command

Quick triage:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001" `
    -CaseNumber "INC-001" `
    -Investigator "Analyst" `
    -Purpose "Initial triage"
```

Full collection:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\WinFire.ps1 -Full -OutputPath "D:\Cases\Case001" `
    -CaseNumber "CASE-001" `
    -Investigator "Analyst" `
    -Purpose "Full forensic collection"
```

Scoped collection:

```powershell
.\WinFire.ps1 -Quick -ExcludeBrowser -ExcludeNetwork -OutputPath "C:\Forensics\Scoped"
```

## Expected AV/EDR Alerts

Security tools may alert because WinFire:

- Enumerates process command lines and executable paths.
- Reads event logs.
- Reads persistence registry keys.
- Copies selected browser artifacts.
- Checks Defender, AV, EDR, Sysmon, AppLocker, WDAC, AMSI, LSA, BitLocker, and TPM state.
- Scans high-risk directories and Alternate Data Streams.
- Enumerates named pipes, WMI subscriptions, ETW/WMI consumers, and kernel drivers.

These actions are legitimate for DFIR, but similar behaviors are also used by threat actors during discovery, staging, and credential-access phases.

## Safer Security-Tool Handling

Prefer a path-specific exclusion:

```powershell
Add-MpPreference -ExclusionPath "C:\Tools\WinFire"
```

Avoid disabling protection globally unless approved. If you must disable real-time monitoring, re-enable it immediately:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001"
Set-MpPreference -DisableRealtimeMonitoring $false
```

Document the action:

```text
Date/Time: 2026-05-06 10:00:00
Action: Added Microsoft Defender exclusion for C:\Tools\WinFire
Reason: Authorized forensic collection
Approver: Security Operations
Removed: 2026-05-06 10:45:00
```

## What WinFire Collects

### System and Users

- OS and hardware information.
- Installed software.
- Environment variables and paths.
- Local users, groups, and memberships.
- User profile artifacts.

### Process, Service, and Persistence

- Running processes and command lines.
- Process hashes where accessible.
- Service status in `Services_Status.csv/.json`.
- Detailed service configuration in `Services_Detail.csv/.json`.
- Scheduled tasks.
- WMI event subscriptions.
- ETW/WMI consumers.
- Kernel drivers and signature status.
- Autorun registry keys.
- COM hijacking indicators.

### Network

- TCP and UDP connections.
- Listening ports.
- Shares and mapped drives.
- Firewall rules.
- Proxy, WinHTTP, and WPAD state.
- Promiscuous-mode adapter properties.
- SMB sessions and open files.
- Named pipes with risk classification.

### File System

- Recent files in high-risk locations.
- Suspicious files based on extension, name, and attributes.
- Startup folder contents.
- Amcache, Prefetch, SRUM, Timeline, and BITS artifacts.
- VSS shadow copies.
- Alternate Data Streams with benign stream classification.

### Event Logs and Browser Artifacts

- Security, System, Application, PowerShell, Defender logs.
- Sysmon status and recent Sysmon events when installed.
- Selected Chrome, Edge, and Firefox artifacts.

### Security Posture

- Defender status and exclusions.
- AV/EDR service detection.
- PowerShell logging configuration.
- AppLocker, WDAC, AMSI, and PowerShell v2 availability.
- Credential Guard, VBS, BitLocker, TPM, and LSA RunAsPPL state.

## Output Review

Primary files:

```text
Reports\WinFire_Executive_Summary.html
Reports\Chain_Of_Custody.json
Reports\Hash_Manifest.txt
Reports\Operation_Metrics.csv
Raw_Data\Threat_Score.csv
WinFire_ExecutionLog.txt
WinFire_Transcript.txt
```

Check for failed operations:

```powershell
Import-Csv "C:\Forensics\Case001\WinFire_Results_YYYYMMDD_HHMMSS\Reports\Operation_Metrics.csv" |
    Where-Object { $_.Status -ne 'Success' }
```

Review score:

```powershell
Import-Csv "C:\Forensics\Case001\WinFire_Results_YYYYMMDD_HHMMSS\Raw_Data\Threat_Score.csv" |
    Format-List
```

## Interpreting Common Warnings

The following can be normal on live systems:

| Warning | Meaning |
| --- | --- |
| Missing `SeBackupPrivilege` or `SeRestorePrivilege` | The elevated token does not have all optional forensic privileges enabled. Some file collection can fail. |
| File cannot be read because it is used by another process | Live files such as temp logs or browser databases are locked. |
| Browser artifact copy failed | Browser process is running and has locked a database/session file. |
| `Amcache.hve` copy status is `Failed` | Windows locked the hive. v2.1.0 records this in `Collected_Amcache.csv/.json`. |
| Sysmon not installed | Reduced telemetry coverage, not necessarily compromise. |
| No VSS shadow copies | Can be normal, but may matter in ransomware/wiper investigations. |
| Named pipe pattern matches | Review `RiskLevel`; low-risk Chromium/Windows patterns are collected but not heavily scored. |
| ADS entries with `StreamedFileState` | Known benign stream name; collected for visibility but not scored as suspicious. |

## Threat Score Guidance

Risk levels:

| Score | Level | Meaning |
| --- | --- | --- |
| 0-10 | Low | Routine findings. |
| 11-30 | Medium | Notable findings. Review warnings. |
| 31-60 | High | Significant triage findings. Prioritize investigation. |
| 61-100 | Critical | Multiple strong indicators. Immediate response may be needed. |

The score is not a verdict. Treat it as a triage aid and validate with raw artifacts, timelines, endpoint telemetry, and analyst judgment.

## Version 2.1.0 Notes

v2.1.0 was updated and runtime-tested with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Help
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Quick -OutputPath .\WinFire_TestRuns -Quiet
```

Latest local quick scan:

- Status: `COMPLETED`
- Operations: `1512 total, 1512 succeeded, 0 failed`
- Output: `WinFire_TestRuns\WinFire_Results_20260506_095301`

## Legal and Privacy Notice

WinFire may collect sensitive personal, system, browser, network, and security configuration data. Use it only when authorized. Protect output as evidence, restrict access, and follow applicable legal, regulatory, privacy, and organizational requirements.

Unauthorized use may violate computer crime, privacy, employment, or data protection laws.
