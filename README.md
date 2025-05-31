# WinFire 🔥
**Windows Forensic Incident Response Engine**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%2FServer%202016%2B-green.svg)](https://www.microsoft.com/windows)

> A comprehensive PowerShell tool for Windows digital forensics and incident response, designed to rapidly collect critical forensic artifacts for security investigations.

```
 █     █░ ██▓ ███▄    █   █████▒██▓ ██▀███  ▓█████ 
▓█░ █ ░█░▓██▒ ██ ▀█   █ ▓██   ▒▓██▒▓██ ▒ ██▒▓█   ▀ 
▒█░ █ ░█ ▒██▒▓██  ▀█ ██▒▒████ ░▒██▒▓██ ░▄█ ▒▒███   
░█░ █ ░█ ░██░▓██▒  ▐▌██▒░▓█▒  ░░██░▒██▀▀█▄  ▒▓█  ▄ 
░░██▒██▓ ░██░▒██░   ▓██░░▒█░   ░██░░██▓ ▒██▒░▒████▒
░ ▓░▒ ▒  ░▓  ░ ▒░   ▒ ▒  ▒ ░   ░▓  ░ ▒▓ ░▒▓░░░ ▒░ ░
  ▒ ░ ░   ▒ ░░ ░░   ░ ▒░ ░      ▒ ░  ░▒ ░ ▒░ ░ ░  ░
  ░   ░   ▒ ░   ░   ░ ░  ░ ░    ▒ ░  ░░   ░    ░   
    ░     ░           ░         ░     ░        ░  ░
```

## 📋 Table of Contents

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
- [License](#license)
- [Disclaimer](#disclaimer)

## 🎯 Overview

WinFire is an all-in-one PowerShell script designed for incident responders, digital forensics investigators, and cybersecurity professionals. It rapidly collects critical forensic artifacts from Windows systems, providing structured output in multiple formats (CSV, JSON, HTML) for immediate analysis or integration with other forensic tools.

### Key Capabilities
- **Rapid Artifact Collection**: Efficiently gathers evidence from running systems
- **Chain of Custody**: Maintains forensic integrity with proper documentation
- **Multi-Format Output**: CSV, JSON, and HTML reports for various analysis workflows
- **Evidence Integrity**: Cryptographic hashing ensures artifact authenticity
- **Flexible Execution**: Quick scans for triage or comprehensive full analysis

## ✨ Features

### 🔍 **System Analysis**
- Operating system and hardware information
- Installed software inventory
- Environment variables and system paths
- Network configuration and interfaces

### 👥 **User Activity Tracking**
- Local user accounts and group memberships
- User profile artifacts and recent file access
- Registry-based user activity (UserAssist, ShellBags)
- Windows Timeline database collection

### 🔄 **Process & Service Analysis**
- Running processes with command lines and hashes
- Windows services and startup configurations
- Scheduled tasks enumeration
- WMI event subscriptions (persistence mechanism)

### 🌐 **Network Forensics**
- Active network connections (TCP/UDP)
- Listening ports and associated processes
- Network shares and mapped drives
- Windows Firewall rules
- SMB sessions and open files

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

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Quick` | Performs rapid scan focusing on high-impact artifacts | False |
| `-Full` | Comprehensive scan collecting all available artifacts | True (if neither specified) |
| `-OutputPath` | Custom directory for output files | Current directory |
| `-CaseNumber` | Forensic case number for chain of custody | "N/A" |
| `-Investigator` | Name of the investigator | "WinFire User" |
| `-Purpose` | Investigation purpose description | "General Forensic Scan" |
| `-HashAlgorithm` | Hashing algorithm (MD5, SHA1, SHA256) | SHA256 |
| `-ExcludeNetwork` | Skip network analysis tasks | False |
| `-ExcludeBrowser` | Skip browser forensics collection | False |
| `-Quiet` | Suppress most console output | False |
| `-Help` | Display detailed help information | False |

## 📦 Collected Artifacts

### Critical Windows Forensic Artifacts

| Artifact Category | Files/Registry Keys | Forensic Value |
|------------------|-------------------|----------------|
| **Execution Evidence** | Amcache.hve, Prefetch/*.pf | Program execution history |
| **User Activity** | ActivitiesCache.db, UserAssist, RecentDocs | User behavior patterns |
| **Persistence** | Run keys, Services, Scheduled Tasks | Malware persistence mechanisms |
| **Network Activity** | Active connections, Firewall rules | Network communication evidence |
| **System Activity** | SRUM database, Event logs | System resource usage and events |
| **Browser Activity** | Chrome/Edge/Firefox profiles | Web browsing history and downloads |
| **USB History** | Registry USB keys | External device usage |
| **File Access** | ShellBags, Recent folder contents | File system navigation |

### Registry Locations Analyzed
```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM:\SYSTEM\CurrentControlSet\Services
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\*
HKLM:\SYSTEM\*ControlSet*\Enum\USB*
```

### Event Log Sources
- **Security.evtx** - Authentication and authorization events
- **System.evtx** - System-level events and service changes
- **Application.evtx** - Application crashes and errors
- **PowerShell/Operational** - Script execution evidence
- **Windows Defender/Operational** - Malware detection events

## 📂 Output Structure

After execution, WinFire creates a timestamped directory with the following structure:

```
WinFire_Results_YYYYMMDD_HHMMSS/
├── Raw_Data/                          # Structured data files
│   ├── System_Information.csv/.json
│   ├── Running_Processes.csv/.json
│   ├── Registry_Autoruns_Persistence.csv/.json
│   ├── Event_Logs.csv/.json
│   └── [Additional CSV/JSON files...]
├── Collected_Artifacts/               # Binary artifacts
│   ├── Browser_Profiles/
│   │   ├── Google_Chrome/
│   │   ├── Microsoft_Edge/
│   │   └── Mozilla_Firefox/
│   ├── Amcache.hve
│   ├── SRUDB.dat
│   ├── Prefetch/
│   └── Timeline/
├── Reports/                           # Analysis reports
│   ├── WinFire_Executive_Summary.html
│   ├── Chain_Of_Custody.json
│   └── Hash_Manifest.txt
└── WinFire_ExecutionLog.txt          # Detailed execution log
```

### Report Types

1. **Executive Summary (HTML)** - Professional report with findings overview
2. **Chain of Custody (JSON)** - Forensic documentation and metadata
3. **Hash Manifest (TXT)** - Cryptographic hashes for evidence integrity
4. **Execution Log (TXT)** - Detailed script execution timeline

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

### Network-Focused Analysis
```powershell
# Skip browser collection, focus on network activity
.\WinFire.ps1 -Full -ExcludeBrowser -OutputPath "C:\NetForensics" `
              -CaseNumber "NET-2024-003" `
              -Purpose "Network intrusion investigation"
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

### Recommended Practices
1. Document investigation scope and authorization
2. Use case numbers and investigator identification
3. Preserve original evidence integrity
4. Follow organizational incident response procedures
5. Coordinate with legal counsel when required

## 🔧 Advanced Configuration

### Custom Artifact Collection
Modify the script to collect additional artifacts by adding new functions:

```powershell
Function Get-CustomArtifacts {
    # Add your custom collection logic here
    # Follow the existing pattern for error handling and output
}
```

### Integration with SIEM/SOC Tools
WinFire's JSON output can be easily integrated with:
- **Splunk** - Import JSON files for timeline analysis
- **Elastic Stack** - Ingest structured data for correlation
- **Microsoft Sentinel** - Upload artifacts for cloud analysis
- **Velociraptor** - Use as supplementary collection source

### Automation Examples

#### PowerShell Remoting
```powershell
# Remote execution across multiple systems
$computers = @("PC001", "PC002", "PC003")
foreach ($computer in $computers) {
    Invoke-Command -ComputerName $computer -FilePath ".\WinFire.ps1" -ArgumentList @("-Quick", "-Quiet")
}
```

#### Scheduled Execution
```powershell
# Create scheduled task for periodic collection
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Tools\WinFire.ps1 -Quick -Quiet"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
Register-ScheduledTask -TaskName "WinFire-DailyCollection" -Action $action -Trigger $trigger
```

## 🔍 Analysis Workflows

### Immediate Triage
1. Run Quick scan for rapid assessment
2. Review Executive Summary HTML report
3. Analyze suspicious processes and network connections
4. Check persistence mechanisms in registry autoruns

### Comprehensive Investigation
1. Execute Full scan with proper case documentation
2. Import JSON data into analysis platforms
3. Correlate artifacts across multiple evidence sources
4. Generate timeline from collected timestamps

### Malware Analysis
1. Focus on execution artifacts (Amcache, Prefetch)
2. Analyze process memory indicators
3. Review PowerShell and security tool logs
4. Examine browser artifacts for download sources

## 🐛 Troubleshooting

### Common Issues

#### Access Denied Errors
```
[WARN] Could not access file: Access Denied
```
**Solution**: Ensure PowerShell is running as Administrator with proper privileges

#### Insufficient Disk Space
```
[WARN] Low disk space detected on 'C' drive
```
**Solution**: Free up disk space or specify different output path with `-OutputPath`

#### Browser Files Locked
```
[WARN] Browser processes detected. Attempting robust copy with RoboCopy
```
**Solution**: This is normal - WinFire uses RoboCopy to handle locked files

#### PowerShell Execution Policy
```
Execution of scripts is disabled on this system
```
**Solution**: 
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### Performance Optimization

#### Large Environments
- Use `-Quick` mode for faster collection
- Exclude browser collection with `-ExcludeBrowser` if not needed
- Exclude network analysis with `-ExcludeNetwork` for offline systems

#### Resource-Constrained Systems
- Monitor disk space before collection
- Use `-Quiet` mode to reduce console overhead
- Consider collecting to external storage device

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
4. Consider implementation approach

### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-artifact`)
3. Follow existing code style and patterns
4. Add appropriate error handling with `Invoke-WinFireSafeOperation`
5. Test thoroughly on different Windows versions
6. Update documentation as needed
7. Commit changes (`git commit -m 'Add amazing new artifact collection'`)
8. Push to branch (`git push origin feature/amazing-artifact`)
9. Open a Pull Request

### Development Guidelines
- Maintain compatibility with PowerShell 5.1+
- Follow existing naming conventions (`Get-WinFire*`)
- Include comprehensive error handling
- Add appropriate logging with `Log-WinFireMessage`
- Update progress tracking and summary reporting
- Test on Windows 10, 11, and Server editions

## 📈 Roadmap

### Planned Features
- [ ] **Memory dump collection** for critical processes
- [ ] **USN Journal analysis** for file system timeline
- [ ] **ETW log collection** for advanced event tracing
- [ ] **Cloud artifact collection** (OneDrive, Office 365)
- [ ] **Mobile device triage** via USB connection
- [ ] **Automated threat hunting** rules integration
- [ ] **API integration** with threat intelligence platforms
- [ ] **Docker container** for portable execution
- [ ] **PowerShell 7 Core** compatibility
- [ ] **Linux subsystem** artifact collection

### Version History
- **v1.0** - Initial release with core forensic collection capabilities

## 📞 Support

### Community Support
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Masriyan/WinFire/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Masriyan/WinFire/discussions)
- 📧 **Contact**: [sudo3rs@protonmail.com](mailto:sudo3rs@protonmail.com)

### Professional Services
For enterprise support, custom development, or training:
- Custom artifact collection development
- Integration with existing SIEM/SOC platforms
- On-site training and workshops
- Forensic investigation consulting

## 🏆 Acknowledgments

### Contributors
- **sudo3rs** - Original author and maintainer
- **Community Contributors** - Feature requests, bug reports, and testing

### Inspiration
WinFire draws inspiration from established forensic tools:
- **KAPE** by Eric Zimmerman
- **CyLR** by Alan Orlikoski
- **Invoke-LiveResponse** by Matt Green
- **PowerForensics** by Jared Atkinson

### Research Sources
- **SANS Digital Forensics** community
- **Windows Incident Response** best practices
- **DFIR Review** artifact analysis
- **13Cubed** educational content

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 sudo3rs

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
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ⚠️ Disclaimer

**IMPORTANT**: WinFire is designed for legitimate digital forensics, incident response, and cybersecurity investigations. Users are responsible for:

- **Legal Compliance**: Ensuring proper authorization before system analysis
- **Scope Adherence**: Operating within authorized investigation boundaries  
- **Data Protection**: Following applicable privacy and data protection laws
- **Professional Use**: Using the tool only for lawful security purposes

### Legal Notice
- This tool is provided for **educational and professional use only**
- Users must obtain **explicit authorization** before analyzing any system
- **Unauthorized use** may violate computer crime and privacy laws
- The authors assume **no liability** for misuse or legal consequences
- Always consult with **legal counsel** for compliance guidance

### Technical Limitations
- Requires **Administrator privileges** for complete artifact collection
- Some artifacts may be **inaccessible** due to system protections
- **Anti-malware software** may flag or block certain collection activities
- Results should be **validated** with additional forensic tools
- **System performance** may be impacted during collection

---

**🔥 Happy Hunting! 🔥**

*WinFire - Illuminating the path to digital truth*
