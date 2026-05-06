# Security Policy

This document covers supported versions, safe use, vulnerability reporting, and data handling for WinFire.

## Supported Versions

| Version | Status | Support |
| --- | --- | --- |
| 2.1.0 | Current | Full support and security fixes |
| 2.0.2 | Legacy | Critical fixes only |
| 2.0.1 | Legacy | Critical fixes only |
| 2.0.0 | Legacy | Critical fixes only |
| 1.0.x | EOL | No support |

## Expected AV and EDR Detection

WinFire will often trigger antivirus, EDR, XDR, or SOC detections. This is expected because the script performs legitimate forensic actions that overlap with attacker tradecraft:

- Enumerates processes, command lines, services, drivers, and scheduled tasks.
- Reads sensitive registry locations.
- Collects browser artifacts and user activity traces.
- Reads event logs and PowerShell history.
- Checks security tools, Defender exclusions, Sysmon, WDAC, AppLocker, AMSI, and LSA protection.
- Scans high-risk file system paths and Alternate Data Streams.
- Enumerates named pipes, WMI subscriptions, and ETW/WMI consumers.

Detection does not automatically mean WinFire is malicious. It means the tool is powerful and should be run under formal authorization.

## Safe Deployment

Before running WinFire:

1. Obtain written authorization.
2. Confirm scope, systems, and data handling requirements.
3. Coordinate with the SOC or security tool owners.
4. Verify the script hash and source.
5. Prepare secure output storage.
6. Run from an elevated PowerShell session.

If security tooling blocks WinFire, prefer a temporary folder-specific exclusion over disabling protection globally:

```powershell
Add-MpPreference -ExclusionPath "C:\Tools\WinFire"
```

If real-time protection must be disabled, document the change and re-enable it immediately after collection:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
.\WinFire.ps1 -Quick -OutputPath "C:\Forensics\Case001"
Set-MpPreference -DisableRealtimeMonitoring $false
```

Document security-tool changes in chain-of-custody notes:

```text
Date/Time: 2026-05-06 10:30:00
Action: Added Microsoft Defender exclusion for C:\Tools\WinFire
Reason: Authorized live forensic collection
Approved by: Security Operations
Removed: 2026-05-06 11:15:00
```

## Data Sensitivity

WinFire output can contain sensitive information.

| Category | Examples | Sensitivity |
| --- | --- | --- |
| System | OS, hardware, software, environment variables | Low to Medium |
| Users | User names, SIDs, profiles, group memberships | Medium |
| Processes | Command lines, executable paths, owners | High |
| Network | IP addresses, ports, shares, firewall rules, proxy state | High |
| Browser | Cookies, history, sessions, profile artifacts where accessible | Very High |
| Event logs | Logons, privilege use, PowerShell, Defender, Sysmon | High |
| Security posture | WDAC, AppLocker, AMSI, LSA, BitLocker, TPM | High |
| Credential indicators | LSASS access and hive-copy indicators | Critical |

Handle results as forensic evidence:

- Store on encrypted media.
- Restrict access to authorized personnel.
- Preserve hash manifests.
- Keep chain-of-custody records.
- Follow legal hold and retention requirements.
- Securely delete temporary copies when no longer needed.

## Reporting Vulnerabilities

Do not report security vulnerabilities in public issues.

Email: sudo3rs@protonmail.com

Subject format:

```text
[SECURITY] Short description
```

Include:

- Vulnerability description.
- Affected version.
- Steps to reproduce.
- Impact.
- Suggested fix if available.
- Whether you want public credit.

### What to Report

Report:

- Code execution vulnerabilities.
- Privilege escalation caused by WinFire code.
- Unsafe file handling that could overwrite unintended paths.
- Sensitive data exposure beyond documented collection.
- Integrity issues in evidence packaging or hash manifests.

Do not report as security issues:

- AV/EDR detection of WinFire.
- Requests for new collection modules.
- General bugs without security impact.
- Documentation typos.

### Response Timeline

| Phase | Target |
| --- | --- |
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix plan | 14 days |
| Coordinated disclosure | After fix release, usually within 30 days |

## Security Best Practices

### Before Collection

- Confirm written authorization.
- Record target hostname, user, time, and purpose.
- Verify script integrity.
- Prepare encrypted evidence storage.
- Record AV/EDR exclusions or policy changes.

### During Collection

- Run as Administrator.
- Use `-Quick` when speed and minimal footprint matter.
- Use `-ExcludeBrowser` or `-ExcludeNetwork` if scope requires it.
- Monitor `WinFire_ExecutionLog.txt` and final execution summary.

### After Collection

- Review `Reports\Operation_Metrics.csv` for failed operations.
- Review `Raw_Data\Threat_Score.csv`.
- Preserve `Reports\Hash_Manifest.txt`.
- Move results to secure storage.
- Remove temporary AV/EDR exclusions.
- Complete chain-of-custody documentation.

## Known Live-System Limitations

The following are expected and should not be treated as script compromise:

- Locked temp files cannot always be hashed.
- Browser files may be locked while browsers are running.
- `Amcache.hve` can be locked; WinFire records failure rows instead of failing the scan.
- `SeBackupPrivilege` and `SeRestorePrivilege` may be disabled even in an elevated session.
- Sysmon may not be installed.
- Some systems have no VSS shadow copies.
- Some named pipe and ADS patterns are benign; v2.1.0 classifies these before scoring.

## Legal Disclaimer

WinFire is intended exclusively for authorized digital forensics, incident response, security assessment, and system administration.

Users are responsible for:

- Authorization.
- Scope control.
- Compliance with applicable laws and regulations.
- Privacy obligations.
- Data protection.
- Chain-of-custody documentation.

The software is provided "as is", without warranty of any kind. The authors and contributors are not responsible for unauthorized use, data loss, system damage, operational disruption, or legal consequences.

Repository: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)
