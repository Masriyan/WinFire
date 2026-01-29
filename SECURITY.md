# Security Policy 🔒

This document outlines security considerations, vulnerability reporting, and important notices for WinFire users.

## 📋 Table of Contents

- [Supported Versions](#-supported-versions)
- [Antivirus Detection](#-antivirus-detection)
- [Reporting Vulnerabilities](#-reporting-vulnerabilities)
- [Security Best Practices](#-security-best-practices)
- [Data Handling](#-data-handling)
- [Legal Disclaimer](#️-legal-disclaimer)

## ✅ Supported Versions

| Version | Status     | Support                        |
| ------- | ---------- | ------------------------------ |
| 2.0.x   | 🟢 Current | Full support, security updates |
| 1.0.x   | 🟡 Legacy  | Critical fixes only            |
| < 1.0   | 🔴 EOL     | No support                     |

## 🛡️ Antivirus Detection

> ⚠️ **WinFire WILL trigger antivirus and EDR alerts. This is expected and normal.**

### Why Detection Occurs

WinFire performs operations that security tools flag as potentially malicious:

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHY AV/EDR DETECTS WINFIRE                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔍 Registry Access           → Reads persistence keys          │
│  📊 Process Enumeration       → Gets all process command lines  │
│  🔐 Credential Artifacts      → Checks LSASS indicators         │
│  🌐 Network Collection        → Enumerates all connections      │
│  📁 Browser Data Access       → Copies profile databases        │
│  📜 Event Log Parsing         → Reads security-sensitive logs   │
│                                                                 │
│  These are LEGITIMATE forensic operations, but they match       │
│  patterns used by threat actors during reconnaissance.          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Handling Detection

#### Option 1: Add Exclusion (Recommended)

```powershell
# Add WinFire folder to Windows Defender exclusions
Add-MpPreference -ExclusionPath "C:\Tools\WinFire"

# Verify exclusion was added
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

#### Option 2: Temporary Disable (Use with Caution)

```powershell
# Disable real-time protection temporarily
Set-MpPreference -DisableRealtimeMonitoring $true

# Run WinFire
.\WinFire.ps1 -Full -OutputPath "C:\Forensics\Case001"

# IMMEDIATELY re-enable protection
Set-MpPreference -DisableRealtimeMonitoring $false
```

#### Option 3: Enterprise/EDR Environments

Contact your security team to:

1. Whitelist the script hash
2. Add process exclusion for PowerShell running WinFire
3. Create approved forensic collection policy

### Document for Chain of Custody

Always record AV handling in your notes:

```
Chain of Custody Note:
- Date/Time: 2026-01-29 10:30:00
- Action: Added Windows Defender exclusion for C:\Tools\WinFire
- Reason: Enable forensic artifact collection
- Removed: 2026-01-29 12:00:00 (after collection complete)
```

## 🐛 Reporting Vulnerabilities

### What to Report

| Report                         | Don't Report              |
| ------------------------------ | ------------------------- |
| Code execution vulnerabilities | AV detection (expected)   |
| Privilege escalation bugs      | Feature requests          |
| Data exfiltration risks        | General bugs (use Issues) |
| Authentication bypasses        | Documentation errors      |

### Report Process

1. **DO NOT** open a public GitHub issue
2. **Email**: sudo3rs@protonmail.com
3. **Subject**: `[SECURITY] Brief Description`
4. **Include**:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

### Response Timeline

| Phase              | Timeframe         |
| ------------------ | ----------------- |
| Acknowledgment     | 48 hours          |
| Initial Assessment | 1 week            |
| Fix Development    | 2 weeks           |
| Disclosure         | 30 days after fix |

### Recognition

Security researchers who responsibly disclose vulnerabilities will be:

- Credited in CHANGELOG.md (unless anonymity requested)
- Acknowledged in release notes
- Added to Security Hall of Fame

## 🔐 Security Best Practices

### Before Collection

```
┌──────────────────────────────────────────────────┐
│           PRE-COLLECTION CHECKLIST               │
├──────────────────────────────────────────────────┤
│ □ Obtain written authorization                   │
│ □ Document system state before collection        │
│ □ Verify script integrity (hash check)           │
│ □ Prepare secure storage for output              │
│ □ Note AV/security tool handling                 │
└──────────────────────────────────────────────────┘
```

### During Collection

- Run from dedicated forensic workstation when possible
- Use case numbers for organization
- Monitor for collection errors in log

### After Collection

```
┌──────────────────────────────────────────────────┐
│          POST-COLLECTION CHECKLIST               │
├──────────────────────────────────────────────────┤
│ □ Verify Hash_Manifest.txt integrity             │
│ □ Move output to encrypted storage               │
│ □ Re-enable any disabled security tools          │
│ □ Remove any temporary exclusions                │
│ □ Complete chain of custody documentation        │
└──────────────────────────────────────────────────┘
```

## 📦 Data Handling

### What WinFire Collects

| Category    | Data Types                    | Sensitivity |
| ----------- | ----------------------------- | ----------- |
| System      | OS info, hardware, software   | Low         |
| Users       | Account names, SIDs, profiles | Medium      |
| Processes   | Names, PIDs, command lines    | High        |
| Network     | IPs, ports, connections       | High        |
| Registry    | Persistence keys, history     | High        |
| Events      | Security logs, logon events   | High        |
| Browser     | Profile databases, history    | Very High   |
| Credentials | LSASS indicators, artifacts   | Critical    |

### Data Protection Requirements

1. **Encrypt at Rest**
   - Use BitLocker on forensic drives
   - Store in encrypted containers
2. **Limit Access**
   - Need-to-know basis only
   - Document all access
3. **Secure Transfer**
   - Use encrypted channels (SFTP, HTTPS)
   - Password-protect ZIP files
4. **Retention**
   - Follow organizational policies
   - Legal hold requirements
   - Securely delete when no longer needed

### Secure Deletion

```powershell
# Securely delete forensic output (Windows)
cipher /w:C:\Forensics\Case001

# Or use SDelete (Sysinternals)
sdelete -p 3 -s C:\Forensics\Case001
```

## ⚖️ Legal Disclaimer

### Authorized Use Only

WinFire is intended **EXCLUSIVELY** for:

- ✅ Digital forensics investigations
- ✅ Authorized incident response
- ✅ Security assessments with written permission
- ✅ System administration on owned systems

### User Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER RESPONSIBILITIES                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📋 AUTHORIZATION                                               │
│     Obtain proper written authorization before use              │
│                                                                 │
│  🎯 SCOPE                                                       │
│     Only collect from authorized systems                        │
│                                                                 │
│  📜 COMPLIANCE                                                  │
│     Follow applicable laws and regulations                      │
│     - GDPR (EU)                                                 │
│     - CCPA (California)                                         │
│     - HIPAA (Healthcare)                                        │
│     - PCI-DSS (Payment data)                                    │
│                                                                 │
│  🔒 PRIVACY                                                     │
│     Respect individual privacy rights                           │
│                                                                 │
│  📝 DOCUMENTATION                                               │
│     Maintain chain of custody for legal proceedings            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors and contributors are not responsible for:

- Unauthorized or illegal use
- Data loss or corruption
- System damage or downtime
- Legal consequences of misuse

**Unauthorized use may violate computer crime laws in your jurisdiction.**

---

**Questions?** Contact: sudo3rs@protonmail.com

**Repository**: [https://github.com/Masriyan/WinFire](https://github.com/Masriyan/WinFire)
