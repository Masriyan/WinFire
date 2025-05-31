# WinFire AV/EDR Detection Analysis

## 🚨 Executive Summary

WinFire triggers AV/EDR detection because it performs **legitimate forensic activities that exactly match malware reconnaissance patterns**. The script's comprehensive system enumeration, file collection, and behavioral analysis capabilities are indistinguishable from advanced persistent threat (APT) tools when viewed through automated detection systems.

---

## 🎯 Primary Detection Triggers

### 1. **Behavioral Pattern Matching**

Modern AV/EDR systems use behavioral analysis to detect malicious activity. WinFire triggers multiple high-confidence indicators:

```powershell
# Process Enumeration (APT Reconnaissance Pattern)
Get-CimInstance Win32_Process | Select-Object CommandLine, ExecutablePath

# Event Log Scraping (Security Bypass Indicator)  
Get-WinEvent -FilterHashtable @{LogName="Security"; StartTime=$timeSpan}

# Registry Enumeration (Persistence Discovery)
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Mass File Operations (Data Exfiltration Pattern)
Copy-Item $browserPath -Recurse -Destination $destPath

# File Hashing (Malware Analysis Behavior)
Get-FileHash -Path $FilePath -Algorithm $HashAlgorithm
```

### 2. **Memory Analysis Patterns**

The memory analysis functions specifically mimic advanced malware techniques:

```powershell
# DLL Enumeration (Process Injection Reconnaissance)
$process.Modules | ForEach-Object {
    ProcessName = $p.ProcessName
    ModuleName  = $_.ModuleName
    FileName    = $_.FileName
    BaseAddress = $_.BaseAddress
}

# Process Hollowing Detection (Anti-Analysis Technique)
$_.MainModule.ModuleName -ne $_.ProcessName

# Suspicious Path Analysis (Malware Staging Detection)
($_.FileName -like "*temp\*" -or $_.FileName -like "*appdata\*")
```

### 3. **Persistence Mechanism Enumeration**

EDR systems heavily monitor persistence locations. WinFire scans all common persistence mechanisms:

```powershell
# Registry Persistence Keys (Malware Installation Pattern)
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

# Scheduled Tasks (Persistence Mechanism)
Get-ScheduledTask | Select-Object TaskName, State, Actions

# WMI Event Subscriptions (Advanced Persistence)
Get-CimInstance -Namespace root\subscription -ClassName '__EventConsumer'
```

---

## 🔍 Specific Code Sections Triggering Detection

### **Line 967-985: Registry Persistence Scanning**
```powershell
# HIGH RISK: This exact pattern matches malware persistence checks
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)
```
**Why Detected**: Identical to malware checking for existing persistence mechanisms before installation.

### **Line 1240-1260: Process Memory Analysis** 
```powershell
# CRITICAL TRIGGER: Advanced malware analysis techniques
Get-Process | Where-Object {
    # Process Hollowing Indicators
    ($_.MainModule.ModuleName -ne $_.ProcessName) -or
    # Unusual Module Counts  
    ($_.Modules.Count -lt 3 -and $_.ProcessName -notmatch "idle|system") -or
    # Memory Anomalies
    ($_.WorkingSet -lt 1MB -and $_.VirtualMemorySize -gt 100MB)
}
```
**Why Detected**: These checks are signature techniques used by rootkits and advanced malware for process analysis.

### **Line 1120-1180: Browser Data Collection**
```powershell
# DATA EXFILTRATION PATTERN: Mass browser data copying
$browsers = @(
    @{Name = "Google Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data"},
    @{Name = "Microsoft Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
    @{Name = "Mozilla Firefox"; Path = "$env:APPDATA\Mozilla\Firefox\Profiles"}
)

# Triggers data theft detection
Copy-Item -Path $browserPath -Destination $destPath -Recurse -Force
```
**Why Detected**: Identical pattern to information stealers and credential harvesting malware.

### **Line 1190-1210: Security Tool Detection**
```powershell
# EVASION TECHNIQUE: Anti-analysis checks
$edrServices = @(
    "CylanceSvc", "CrowdStrike Falcon Sensor", "CarbonBlack", 
    "SentinelAgent", "Elastic Agent", "McAfee Agent"
)
Get-Service -Name $serviceName -ErrorAction SilentlyContinue
```
**Why Detected**: This exact pattern is used by malware for AV/EDR evasion before payload deployment.

### **Line 162-180: Privilege Escalation Patterns**
```powershell
# PRIVILEGE ESCALATION: Advanced permission checks
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$requiredPrivileges = @("SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege")
```
**Why Detected**: Checking for debug and backup privileges is a classic malware technique for gaining system-level access.

---

## 🎯 Machine Learning Detection Triggers

### **Entropy Analysis**
- **High Entropy Strings**: Base64-like data from JSON serialization
- **Compressed Data Patterns**: `ConvertTo-Json -Compress` output resembles encoded payloads
- **Repetitive API Calls**: Looped cmdlet execution patterns match automated tools

### **API Call Sequences**
The following sequence specifically triggers ML-based detection:
```
1. Administrator Check → 2. Process Enumeration → 3. Registry Scanning → 
4. File Hashing → 5. Mass File Operations → 6. Security Tool Detection
```

### **Statistical Anomalies**
- **Volume of Operations**: 30+ major forensic operations in sequence
- **System Coverage**: Touching all major Windows subsystems rapidly
- **Data Collection Rate**: High-velocity artifact gathering

---

## 🔧 EDR-Specific Detection Mechanisms

### **CrowdStrike Falcon**
| Detection Engine | Triggered By | Line References |
|-----------------|--------------|-----------------|
| **Process Injection Detection** | Module enumeration across all processes | Lines 1225-1250 |
| **Registry Persistence Scanning** | Autorun location enumeration | Lines 967-985 |
| **Mass File Operations** | Browser profile copying with RoboCopy | Lines 1120-1180 |
| **Behavioral Analysis** | Admin check + process enum + file ops sequence | Lines 162-180, 450-500 |

### **Microsoft Defender**
| Detection Component | Triggered By | Risk Level |
|--------------------|--------------|------------|
| **AMSI (AntiMalware Scan Interface)** | PowerShell script content analysis | **HIGH** |
| **Cloud Reputation** | Script hash matching forensic tool patterns | **MEDIUM** |
| **Behavioral Monitoring** | Privilege checks + system enumeration | **HIGH** |
| **Machine Learning** | Statistical pattern matching | **CRITICAL** |

### **Carbon Black**
| Monitor Type | Detection Trigger | Script Impact |
|-------------|------------------|---------------|
| **Process Tree Analysis** | PowerShell → Admin check → Process enum | Immediate detection |
| **File System Events** | Bulk operations to temp directories | Hash collection triggers |
| **Registry Monitoring** | Rapid autorun key enumeration | Persistence scan detection |
| **Network Behavior** | Data staging patterns (even offline) | Collection phase triggers |

---

## 💡 Comparative Analysis: Why WinFire vs Other Tools

### **WinFire vs KAPE**
| Factor | WinFire | KAPE | Detection Impact |
|--------|---------|------|------------------|
| **Language** | Pure PowerShell | Compiled C# | PowerShell = Higher detection (AMSI) |
| **Execution Method** | Script interpretation | Binary execution | Scripts = More behavioral triggers |
| **System Integration** | Deep Windows API usage | File-based collection | API calls = More monitoring points |
| **Privilege Handling** | Inline checks | Pre-validated | Dynamic checks = Privilege escalation detection |

### **WinFire vs CyLR**
| Aspect | WinFire | CyLR | Why WinFire Detected More |
|--------|---------|------|--------------------------|
| **Memory Analysis** | Comprehensive process/DLL analysis | Limited memory artifacts | Advanced techniques trigger APT detection |
| **Registry Scanning** | Full persistence enumeration | Selective key collection | Comprehensive scanning = Malware pattern |
| **Browser Forensics** | Live process-aware copying | Static file collection | Process interaction = Data theft pattern |
| **Security Awareness** | Active AV/EDR detection | Passive collection | Security scanning = Evasion attempt |

---

## 🛡️ Detection Mitigation Strategies

### **1. Pre-Execution AV Compatibility Check**
```powershell
Function Test-WinFireAVCompatibility {
    param([switch]$Quiet)
    
    # Detect active security products
    $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    if ($defenderStatus.RealTimeProtectionEnabled -or $avProducts.Count -gt 0) {
        Write-Warning @"
⚠️  ACTIVE ANTIVIRUS DETECTED ⚠️
WinFire may be blocked or quarantined by security software.

Detected Products: $($avProducts.DisplayName -join ', ')
Windows Defender Real-time: $($defenderStatus.RealTimeProtectionEnabled)

RECOMMENDED ACTIONS:
1. Add WinFire directory to AV exclusions
2. Coordinate with security team before execution  
3. Use stealth mode: -StealthMode parameter
4. Consider offline analysis environment

Current Script Path: $PSScriptRoot
"@
        
        if (-not $Quiet) {
            $response = Read-Host "Continue execution anyway? (y/N)"
            if ($response -notlike "y*") {
                Write-Host "Execution cancelled for security compliance." -ForegroundColor Yellow
                exit 1
            }
        }
    }
}
```

### **2. Stealth Mode Implementation**
```powershell
# Add to parameter block
[Parameter()]
[switch]$StealthMode

# Modify high-risk functions
if ($StealthMode) {
    # Reduce detection footprint
    $ExcludeBrowser = $true
    $script:SkipMemoryAnalysis = $true  
    $script:LimitedRegistryScanning = $true
    $script:ReducedProcessEnum = $true
    
    Write-Host "🥷 Stealth mode enabled - Reducing AV detection footprint" -ForegroundColor DarkCyan
    Get-WinFireSummaryEntry -Category "Execution Mode" -Description "Stealth mode active - Limited collection to avoid detection" -Status "Info"
}
```

### **3. Rate-Limited Operations**
```powershell
Function Invoke-RateLimitedOperation {
    param(
        [scriptblock]$Operation,
        [string]$OperationName,
        [int]$DelayMs = 100
    )
    
    # Add delay to avoid triggering behavioral detection
    if ($script:UseRateLimiting) {
        Start-Sleep -Milliseconds $DelayMs
    }
    
    return Invoke-WinFireSafeOperation -Operation $Operation -OperationName $OperationName -Quiet:$Quiet
}
```

### **4. Enterprise Deployment Solutions**

#### **AV Exclusion Commands**
```powershell
# Windows Defender Exclusions (Administrator required)
Add-MpPreference -ExclusionPath "C:\Tools\WinFire\"
Add-MpPreference -ExclusionProcess "powershell.exe"  
Add-MpPreference -ExclusionExtension ".ps1"

# Verify exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

#### **Group Policy Deployment**
```xml
<!-- AppLocker Policy for WinFire -->
<RuleCollection Type="Script" EnforcementMode="Enabled">
    <FileHashRule Id="WinFire-Approved" Name="WinFire Forensic Tool" 
                  Description="Approved DFIR tool" 
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
        <FileHash Type="SHA256" 
                  Data="[WINFIRE_SHA256_HASH]" 
                  SourceFileName="WinFire.ps1" />
    </FileHashRule>
</RuleCollection>
```

#### **SCCM/Intune Package**
```powershell
# Package deployment with AV exclusions
Configuration WinFireDeployment {
    Node "localhost" {
        # Deploy script
        File WinFireScript {
            DestinationPath = "C:\Tools\WinFire\WinFire.ps1"
            SourcePath = "\\deploy\WinFire.ps1" 
            Ensure = "Present"
        }
        
        # Configure AV exclusions
        Script ConfigureAVExclusions {
            SetScript = {
                Add-MpPreference -ExclusionPath "C:\Tools\WinFire\"
                Add-MpPreference -ExclusionProcess "powershell.exe"
            }
            TestScript = { 
                $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
                return ($exclusions -contains "C:\Tools\WinFire\")
            }
            GetScript = { @{ Result = "AV exclusion configuration" } }
        }
    }
}
```

---

## 📋 Deployment Recommendations

### **For IT Administrators**
1. **📧 Pre-coordinate with Security Teams**: Notify SOC/Security teams before deployment
2. **🛡️ Implement AV Exclusions**: Use Group Policy for organization-wide exclusions  
3. **📝 Document Usage**: Maintain audit trail of forensic tool deployments
4. **🔐 Code Sign Scripts**: Use organizational certificates to establish trust
5. **🌐 Isolated Networks**: Deploy on dedicated forensic analysis networks when possible

### **For Incident Responders**
1. **⚡ Use Quick Mode**: `-Quick` parameter reduces detection surface
2. **🎭 Enable Stealth Mode**: `-StealthMode` for sensitive environments
3. **📞 Coordinate with IT**: Request temporary exclusion policies
4. **💾 Alternative Execution**: Consider memory-only execution or remote deployment
5. **📊 Monitor Detection**: Log AV interactions for investigation documentation

### **For Security Engineers**
1. **🔍 Whitelist Hash**: Add WinFire hash to security tool allowlists
2. **📈 Tune Detection Rules**: Adjust behavioral detection for known forensic tools
3. **🏗️ Create Deployment Pipeline**: Automated deployment with proper exclusions
4. **📋 Incident Response Integration**: Include WinFire in standard IR procedures
5. **🔄 Regular Updates**: Maintain current tool versions and hash databases

---

## 🔗 Additional Resources

### **AV Vendor-Specific Exclusion Guides**
- **Microsoft Defender**: [Configure exclusions based on file extension and folder location](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus)
- **CrowdStrike**: [Falcon exclusion management](https://falcon.crowdstrike.com/support/documentation/1/falcon-exclusions)
- **Carbon Black**: [Sensor exclusion configuration](https://community.carbonblack.com/t5/Knowledge-Base/Carbon-Black-Cloud-How-to-Exclude-Files-Folders-and-Processes/ta-p/93497)

### **Enterprise Deployment Tools**
- **SCCM Integration**: [PowerShell DSC for automated deployment](https://docs.microsoft.com/en-us/powershell/scripting/dsc/overview/overview)
- **Ansible Playbooks**: [Windows forensic tool deployment automation](https://docs.ansible.com/ansible/latest/collections/ansible/windows/)
- **Group Policy Management**: [Software installation and security policies](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581922(v=ws.11))

---

## ⚠️ Important Notes

> **Legal Compliance**: Always ensure proper authorization before deploying forensic tools in production environments.

> **Security Coordination**: Coordinate with security teams to avoid triggering incident response procedures.

> **Documentation**: Maintain detailed logs of tool deployment and usage for compliance and audit purposes.

> **Version Control**: Keep forensic tools updated and maintain hash verification for integrity.

The key insight is that **WinFire's comprehensive forensic capabilities make it indistinguishable from advanced malware** when viewed through automated detection systems. The solution is **proper coordination, exclusion management, and deployment procedures** rather than reducing the tool's effectiveness.
