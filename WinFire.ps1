# region CmdletBinding and Parameters (MUST BE AT THE VERY TOP OF THE SCRIPT FILE)
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(ParameterSetName='Default')]
    [switch]$Quick,

    [Parameter(ParameterSetName='Default')]
    [switch]$Full,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$ExcludeNetwork,
    [switch]$ExcludeBrowser,

    [ValidateSet('MD5', 'SHA1', 'SHA256')]
    [string]$HashAlgorithm = 'SHA256',

    [switch]$Quiet,

    [Parameter(Mandatory=$false)]
    [string]$CaseNumber,

    [Parameter(Mandatory=$false)]
    [string]$Investigator,

    [Parameter(Mandatory=$false)]
    [string]$Purpose,

    [Parameter(Mandatory=$true, ParameterSetName='Help')]
    [switch]$Help
)
# endregion

<#
.SYNOPSIS
    WinFire (Windows Forensic Incident Response Engine) - A comprehensive PowerShell tool for Windows digital forensics and incident response.

.DESCRIPTION
    WinFire is an all-in-one script designed to collect critical forensic artifacts from a Windows system quickly and efficiently.
    It gathers system information, user activities, process and network data, file system details, registry artifacts,
    event logs, and persistence mechanisms. The output is structured, includes various formats (CSV, JSON, HTML),
    and is packaged for easy analysis.

.PARAMETER Quick
    Performs a quick scan, focusing on essential and high-impact artifacts.
    This mode is faster and collects less data compared to a full scan.

.PARAMETER Full
    Performs a comprehensive scan, collecting all available artifacts.
    This mode is more thorough but takes significantly longer and generates more data.

.PARAMETER OutputPath
    Specifies a custom directory where all collected data and reports will be saved.
    If not specified, a timestamped directory will be created in the current working directory.

.PARAMETER ExcludeNetwork
    Skips all network analysis tasks.

.PARAMETER ExcludeBrowser
    Skips all browser forensics tasks. Note: Browser forensics primarily involves collecting cache/profile files for external analysis.

.PARAMETER HashAlgorithm
    Specifies the hashing algorithm to use for collected files.
    Valid values are 'MD5', 'SHA1', and 'SHA256'. Default is 'SHA256'.

.PARAMETER Quiet
    Suppresses most console output, showing only critical errors and a final summary.
    Progress indicators will still be displayed.

.PARAMETER CaseNumber
    Specifies the forensic case number for chain of custody documentation.

.PARAMETER Investigator
    Specifies the name of the investigator for chain of custody documentation.

.PARAMETER Purpose
    Specifies the purpose of the investigation for chain of custody documentation.

.PARAMETER Help
    Displays this help message.

.EXAMPLE
    .\WinFire.ps1 -Quick -OutputPath C:\Forensics\Case123 -CaseNumber 2023-001 -Investigator "John Doe" -Purpose "Malware Analysis"

.EXAMPLE
    .\WinFire.ps1 -Full -ExcludeBrowser -HashAlgorithm SHA1 -CaseNumber "INC-2024-005"

.EXAMPLE
    .\WinFire.ps1 -Help

.NOTES
    WinFire (Windows Forensic Incident Response Engine)
    Version: 2.0
    Author: sudo3rs
    Description: Comprehensive Windows Digital Forensics and Incident Response Tool
    Compatible: Windows 10/11/Server 2016+
    Requires: PowerShell 5.1+ with Administrator privileges
    License: MIT License (or specify your chosen open-source license)
    Disclaimer: This script is for educational and forensic purposes. Use responsibly.
#>

#region Header and Metadata

# WinFire (Windows Forensic Incident Response Engine)
# Version: 2.0
# Author: sudo3rs
# Description: Comprehensive Windows Digital Forensics and Incident Response Tool
# Compatible: Windows 10/11/Server 2016+
# Requires: PowerShell 5.1+ with Administrator privileges

#endregion

#region Global Variables and Preferences

# Set strict mode for better coding practices
Set-StrictMode -Version Latest

# Error handling preference: continue on non-terminating errors, but log them
$ErrorActionPreference = 'Continue'

# Global variables for output paths
$script:OutputPath      = $null
$script:LogPath         = $null
$script:SummaryReport   = @() # Stores key findings for the HTML report
$script:CollectedFiles  = @() # Stores info about collected files for hash manifest
$script:StartTime       = Get-Date
$script:ProgressCounter = 0
$script:TotalTasks      = 40 # Approximate number of major tasks for progress bar (v2.0 - added 10 new functions)
$script:ChainOfCustody  = $null

#endregion

#region Helper Functions

Function Show-WinFireBanner {
    <#
    .SYNOPSIS
        Displays the WinFire ASCII art banner with flame effects.
    #>
    param()
    Write-Host ""
    Write-Host "                          )  (      (     " -ForegroundColor DarkYellow
    Write-Host "                         (   ) )    )\ )  " -ForegroundColor Yellow
    Write-Host "                          ) ( (    (()/(  " -ForegroundColor Red
    Write-Host "                         (   ))\    /(_)) " -ForegroundColor DarkRed
    Write-Host ""
    Write-Host "  ██╗    ██╗██╗███╗   ██╗███████╗██╗██████╗ ███████╗" -ForegroundColor Red
    Write-Host "  ██║    ██║██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝" -ForegroundColor Red
    Write-Host "  ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║██████╔╝█████╗  " -ForegroundColor DarkRed
    Write-Host "  ██║███╗██║██║██║╚██╗██║██╔══╝  ██║██╔══██╗██╔══╝  " -ForegroundColor DarkRed
    Write-Host "  ╚███╔███╔╝██║██║ ╚████║██║     ██║██║  ██║███████╗" -ForegroundColor Red
    Write-Host "   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
    Write-Host "  ║   " -ForegroundColor DarkGray -NoNewline
    Write-Host "Windows Forensic Incident Response Engine" -ForegroundColor Cyan -NoNewline
    Write-Host "              ║" -ForegroundColor DarkGray
    Write-Host "  ║   " -ForegroundColor DarkGray -NoNewline
    Write-Host "Version: 2.0" -ForegroundColor Green -NoNewline
    Write-Host "  |  Author: " -ForegroundColor DarkGray -NoNewline
    Write-Host "sudo3rs" -ForegroundColor Yellow -NoNewline
    Write-Host "                        ║" -ForegroundColor DarkGray
    Write-Host "  ║   " -ForegroundColor DarkGray -NoNewline
    Write-Host "https://github.com/Masriyan/WinFire" -ForegroundColor Blue -NoNewline
    Write-Host "                       ║" -ForegroundColor DarkGray
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [" -ForegroundColor White -NoNewline
    Write-Host "!" -ForegroundColor Yellow -NoNewline
    Write-Host "] " -ForegroundColor White -NoNewline
    Write-Host "Comprehensive DFIR artifact collection for Windows systems" -ForegroundColor Gray
    Write-Host ""
}

Function Test-WinFireAdminPrivileges {
    <#
    .SYNOPSIS
        Checks if the script is running with administrator privileges and required forensic privileges.
    #>
    param()
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "WinFire requires Administrator privileges to run. Please run PowerShell as Administrator."
        Log-WinFireMessage -Type ERROR -Message "Script started without Administrator privileges. Exiting."
        exit 1
    }

    Log-WinFireMessage -Type INFO -Message "Administrator privileges confirmed." -Quiet:$Quiet

    # Additional check for specific privileges needed for forensics (SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege)
    # Note: PowerShell can't directly enable these without external modules or P/Invoke.
    # We check if the current process *has* them. If running as Admin, they are usually present.
    $requiredPrivileges = @("SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege")
    $missingPrivileges = @()

    foreach ($priv in $requiredPrivileges) {
        try {
            $hasPriv = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Privileges | Where-Object { $_.Name -eq $priv -and $_.Attributes -match 'Enabled' })
            if (-not $hasPriv) {
                $missingPrivileges += $priv
            }
        }
        catch {
            Log-WinFireMessage -Type WARN -Message "Could not check privilege '$priv': $_" -Quiet:$Quiet
        }
    }

    if ($missingPrivileges.Count -gt 0) {
        Log-WinFireMessage -Type WARN -Message "The following important forensic privileges appear to be missing or disabled: $($missingPrivileges -join ', '). Some operations may fail." -Quiet:$Quiet
        Get-WinFireSummaryEntry -Category "Privileges" -Description "Missing or disabled required forensic privileges." -Status "Warning" -Details "Missing: $($missingPrivileges -join ', ')"
    } else {
        Log-WinFireMessage -Type INFO -Message "All essential forensic privileges appear to be enabled." -Quiet:$Quiet
        Get-WinFireSummaryEntry -Category "Privileges" -Description "All essential forensic privileges enabled." -Status "Success" -Details "SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege"
    }

    return $true
}

Function Log-WinFireMessage {
    <#
    .SYNOPSIS
        Logs messages to a file and optionally to the console.
    .PARAMETER Type
        The type of message (INFO, WARN, ERROR, SUCCESS, PROGRESS).
    .PARAMETER Message
        The message string to log.
    .PARAMETER Quiet
        If set to $true, suppresses console output for INFO messages.
    #>
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'PROGRESS')]
        [string]$Type,
        [string]$Message,
        [switch]$Quiet
    )

    $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
    $logEntry = "[$timestamp] [$Type] $Message"

    # Write to log file
    try {
        Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not write to log file: $_. Log Entry: $logEntry"
    }

    # Write to console based on type and Quiet parameter
    switch ($Type) {
        'INFO' { if (-not $Quiet) { Write-Host "$Message" -ForegroundColor Cyan } }
        'WARN' { Write-Warning "$Message" }
        'ERROR' { Write-Error "$Message" }
        'SUCCESS' { Write-Host "$Message" -ForegroundColor Green }
        'PROGRESS' { # Do not write progress to console via this function, handled by Set-WinFireProgress
            if (-not $Quiet) { Write-Host "$Message" -ForegroundColor DarkGray }
        }
    }
}

Function New-WinFireOutputDirectory {
    <#
    .SYNOPSIS
        Creates the output directory structure for WinFire.
    .PARAMETER BasePath
        The base path where the output directory will be created.
    #>
    param(
        [string]$BasePath
    )
    $timestampDir = (Get-Date -Format "yyyyMMdd_HHmmss")
    $script:OutputPath = Join-Path -Path $BasePath -ChildPath "WinFire_Results_$timestampDir"
    $script:LogPath = Join-Path -Path $script:OutputPath -ChildPath "WinFire_ExecutionLog.txt"

    try {
        New-Item -ItemType Directory -Path $script:OutputPath -ErrorAction Stop | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:OutputPath "Raw_Data") -ErrorAction Stop | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:OutputPath "Collected_Artifacts") -ErrorAction Stop | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:OutputPath "Reports") -ErrorAction Stop | Out-Null
        Log-WinFireMessage -Type INFO -Message "Output directory created: $($script:OutputPath)" -Quiet:$Quiet
        Log-WinFireMessage -Type INFO -Message "Logging to: $($script:LogPath)" -Quiet:$Quiet
    }
    catch {
        Write-Error "Failed to create output directory: $_"
        exit 1
    }
}

Function Get-FileHashSafe {
    <#
    .SYNOPSIS
        Calculates the hash of a file safely, handling access denied errors.
    .PARAMETER FilePath
        The path to the file.
    .PARAMETER Algorithm
        The hashing algorithm to use (MD5, SHA1, SHA256).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [ValidateSet('MD5', 'SHA1', 'SHA256')]
        [string]$Algorithm
    )
    try {
        if (Test-Path -Path $FilePath -PathType Leaf) {
            return (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop).Hash
        }
    }
    catch {
        Log-WinFireMessage -Type WARN -Message "Could not hash file '$FilePath': $_" -Quiet:$Quiet
    }
    return "N/A"
}

Function Save-WinFireData {
    <#
    .SYNOPSIS
        Saves collected data to CSV and JSON formats.
    .PARAMETER Data
        The data (array of objects) to save.
    .PARAMETER FileName
        The base name for the output files (e.g., "SystemInfo").
    .PARAMETER Quiet
        If set to $true, suppresses console output for INFO messages.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Data,
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [switch]$Quiet
    )
    $csvPath = Join-Path -Path $script:OutputPath -ChildPath "Raw_Data\$FileName.csv"
    $jsonPath = Join-Path -Path $script:OutputPath -ChildPath "Raw_Data\$FileName.json"

    if ($Data -and $Data.Count -gt 0) {
        try {
            $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
            Log-WinFireMessage -Type INFO -Message "Data saved to: $csvPath" -Quiet:$Quiet

            $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8 -Force -ErrorAction Stop
            Log-WinFireMessage -Type INFO -Message "Data saved to: $jsonPath" -Quiet:$Quiet
        }
        catch {
            Log-WinFireMessage -Type ERROR -Message "Failed to save $FileName data: $_" -Quiet:$Quiet
        }
    } else {
        Log-WinFireMessage -Type INFO -Message "No data collected for $FileName." -Quiet:$Quiet
    }
}

Function Set-WinFireProgress {
    <#
    .SYNOPSIS
        Updates the progress bar and displays current task.
    .PARAMETER Activity
        The current activity being performed.
    .PARAMETER Status
        The current status of the activity.
    .PARAMETER CurrentValue
        The current progress value.
    .PARAMETER MaxValue
        The maximum progress value (total tasks).
    #>
    param(
        [string]$Activity,
        [string]$Status,
        [int]$CurrentValue,
        [int]$MaxValue
    )
    if ($MaxValue -eq 0) { $percentComplete = 0 } else { $percentComplete = [int](($CurrentValue / $MaxValue) * 100) }

    # Avoid division by zero for SecondsRemaining if CurrentValue is 0
    $secondsRemaining = $null
    if ($CurrentValue -gt 0) {
        $secondsRemaining = (New-TimeSpan -Start $script:StartTime -End (Get-Date)).TotalSeconds * ($MaxValue - $CurrentValue) / $CurrentValue
    }

    Write-Progress -Activity "WinFire Scan: $Activity" -Status $Status -CurrentOperation "Processing..." -PercentComplete $percentComplete -SecondsRemaining $secondsRemaining
}

Function Get-WinFireSummaryEntry {
    <#
    .SYNOPSIS
        Creates a summary entry for the HTML report.
    #>
    param(
        [string]$Category,
        [string]$Description,
        [string]$Status,
        [string]$Details = "N/A"
    )
    $script:SummaryReport += [PSCustomObject]@{
        Category    = $Category
        Description = $Description
        Status      = $Status
        Details     = $Details
    }
}

Function Invoke-WinFireSafeOperation {
    <#
    .SYNOPSIS
        A wrapper function to execute an operation with comprehensive error handling and logging.
    .PARAMETER Operation
        The scriptblock containing the operation to execute.
    .PARAMETER OperationName
        A descriptive name for the operation.
    .PARAMETER Quiet
        If set to $true, suppresses console output for INFO messages.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$Operation,
        [Parameter(Mandatory=$true)]
        [string]$OperationName,
        [switch]$Quiet
    )

    Log-WinFireMessage -Type INFO -Message "Starting '$OperationName'..." -Quiet:$Quiet
    $result = $null
    try {
        # Temporarily change ErrorActionPreference for the scriptblock to capture specific errors
        $oldErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $result = & $Operation
        $ErrorActionPreference = $oldErrorActionPreference # Restore original preference

        Log-WinFireMessage -Type SUCCESS -Message "'$OperationName' completed successfully." -Quiet:$Quiet
        return $result
    }
    catch [System.UnauthorizedAccessException] {
        Log-WinFireMessage -Type WARN -Message "'$OperationName' failed: Access Denied - $_" -Quiet:$Quiet
        Get-WinFireSummaryEntry -Category "Error: $OperationName" -Description "Access Denied during operation." -Status "Failed" -Details "$_"
    }
    catch [System.IO.IOException] {
        Log-WinFireMessage -Type WARN -Message "'$OperationName' failed: IO Error (file locked/in use) - $_" -Quiet:$Quiet
        Get-WinFireSummaryEntry -Category "Error: $OperationName" -Description "IO Error during operation." -Status "Warning" -Details "$_"
    }
    catch {
        Log-WinFireMessage -Type ERROR -Message "'$OperationName' failed: $_" -Quiet:$Quiet
        Get-WinFireSummaryEntry -Category "Error: $OperationName" -Description "Unexpected error during operation." -Status "Failed" -Details "$_"
    }
    finally {
        # Ensure ErrorActionPreference is restored even if an error occurred before explicit restoration
        $ErrorActionPreference = $oldErrorActionPreference
    }
    return $null
}

Function Initialize-WinFireChainOfCustody {
    <#
    .SYNOPSIS
        Initializes and logs chain of custody information.
    .PARAMETER CaseNumber
        The forensic case number.
    .PARAMETER Investigator
        The name of the investigator.
    .PARAMETER Purpose
        The purpose of the investigation.
    #>
    param(
        [string]$CaseNumber = "N/A",
        [string]$Investigator = "WinFire User",
        [string]$Purpose = "General Forensic Scan"
    )

    $systemTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff zzz"
    $utcTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff UTC")

    $systemUptime = Invoke-WinFireSafeOperation -Operation {
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    } -OperationName "Get System Uptime" -Quiet:$Quiet | ForEach-Object { [System.Management.ManagementDateTimeConverter]::ToDateTime($_) }

    $kernelHash = Invoke-WinFireSafeOperation -Operation {
        Get-FileHash -Path "$env:SystemRoot\System32\ntoskrnl.exe" -Algorithm SHA256
    } -OperationName "Hash ntoskrnl.exe" -Quiet:$Quiet | Select-Object -ExpandProperty Hash

    $script:ChainOfCustody = [PSCustomObject]@{
        CaseNumber      = $CaseNumber
        Investigator    = $Investigator
        Purpose         = $Purpose
        SystemTime      = $systemTime
        UTCTime         = $utcTime
        ComputerName    = $env:COMPUTERNAME
        UserName        = $env:USERNAME
        SystemUptime    = $systemUptime.ToString('yyyy-MM-dd HH:mm:ss')
        NtOsKrnlHash    = $kernelHash
        WinFireVersion  = "2.0"
        ScanStartTime   = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
        OutputDirectory = $script:OutputPath
        ExecutionLog    = $script:LogPath
    }

    $custodyInfoJson = $script:ChainOfCustody | ConvertTo-Json -Depth 5 -Compress
    Set-Content -Path (Join-Path $script:OutputPath "Reports\Chain_Of_Custody.json") -Value $custodyInfoJson -Encoding UTF8 -Force
    Log-WinFireMessage -Type INFO -Message "Chain of Custody information initialized and saved." -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Chain of Custody" -Description "Basic chain of custody information collected." -Status "Success" -Details "Case: $CaseNumber, Investigator: $Investigator"
}

#endregion

#region Core Forensic Functions

Function Get-WinFireSystemInfo {
    <#
    .SYNOPSIS
        Collects basic system information.
    #>
    param(
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "System Information" -Status "Collecting core system details..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $systemInfo = @()

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "OS_Info"
            Data     = (Get-CimInstance Win32_OperatingSystem | Select-Object -Property Caption, Version, BuildNumber, OSArchitecture, @{Name='InstallDate'; Expression={$_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss')}}, LastBootUpTime, @{Name='LastBootUpTimeReadable'; Expression={[System.Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime)}}, SystemDirectory, FreePhysicalMemory, TotalPhysicalMemory, Locale) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect OS Info" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "Computer_Info"
            Data     = (Get-CimInstance Win32_ComputerSystem | Select-Object -Property Name, Domain, Workgroup, Manufacturer, Model, PrimaryOwnerName, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect Computer Info" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "BIOS_Info"
            Data     = (Get-CimInstance Win32_BIOS | Select-Object -Property Manufacturer, Version, SMBIOSBIOSVersion, ReleaseDate) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect BIOS Info" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "CPU_Info"
            Data     = (Get-CimInstance Win32_Processor | Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect CPU Info" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "Timezone_Info"
            Data     = (Get-CimInstance Win32_TimeZone | Select-Object -Property Description, StandardName, Bias) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect Timezone Info" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "Network_Configuration"
            Data     = (Get-NetIPConfiguration | Select-Object -Property InterfaceAlias, IPv4Address, IPv6Address, DNSServer, MacAddress, ConnectionSpecificSuffix) | ConvertTo-Json -Compress
        }
    } -OperationName "Collect Network Configuration" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "DNS_Cache"
            Data     = (ipconfig /displaydns | Out-String)
        }
    } -OperationName "Collect DNS Cache" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "ARP_Table"
            Data     = (arp -a | Out-String)
        }
    } -OperationName "Collect ARP Table" -Quiet:$Quiet

    $systemInfo += Invoke-WinFireSafeOperation -Operation {
        [PSCustomObject]@{
            Category = "Routing_Table"
            Data     = (route print | Out-String)
        }
    } -OperationName "Collect Routing Table" -Quiet:$Quiet

    # Using registry for installed software for efficiency (Win32_Product is slow)
    $installedSoftwareReg = Invoke-WinFireSafeOperation -Operation {
        $soft = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        $soft += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        $soft | Where-Object {$_.DisplayName -ne $null} | Select-Object -Unique DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    } -OperationName "Collect Installed Software" -Quiet:$Quiet
    if ($installedSoftwareReg) {
        $systemInfo += [PSCustomObject]@{
            Category = "Installed_Software"
            Data     = $installedSoftwareReg | ConvertTo-Json -Compress
        }
    }

    $environmentVars = Invoke-WinFireSafeOperation -Operation {
        Get-Item Env:* | Select-Object Name, Value
    } -OperationName "Collect Environment Variables" -Quiet:$Quiet
    if ($environmentVars) {
        $systemInfo += [PSCustomObject]@{
            Category = "Environment_Variables"
            Data     = $environmentVars | ConvertTo-Json -Compress
        }
    }

    $systemPaths = Invoke-WinFireSafeOperation -Operation {
        $env:Path.Split(';') | ForEach-Object { [PSCustomObject]@{Path = $_} }
    } -OperationName "Collect System Paths" -Quiet:$Quiet
    if ($systemPaths) {
        $systemInfo += [PSCustomObject]@{
            Category = "System_Paths"
            Data     = $systemPaths | ConvertTo-Json -Compress
        }
    }

    Save-WinFireData -Data $systemInfo -FileName "System_Information" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "System Info" -Description "Collected OS, Hardware, Network, and Software details." -Status "Success" -Details "Collected $(($systemInfo | Measure-Object).Count) system info categories."
}

Function Get-WinFireUserAccounts {
    <#
    .SYNOPSIS
        Collects user account details and related artifacts.
    #>
    param(
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "User Account Analysis" -Status "Enumerating users and their profiles..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $localUsers = $null
    $groupMemberships = @()
    $userProfileArtifacts = @()

    $localUsers = Invoke-WinFireSafeOperation -Operation {
        Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, PasswordRequired, @{Name='IsAdmin'; Expression={(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")}}, SID
    } -OperationName "Collect Local User Accounts" -Quiet:$Quiet
    Save-WinFireData -Data $localUsers -FileName "User_Accounts" -Quiet:$Quiet

    $localGroups = Invoke-WinFireSafeOperation -Operation { Get-LocalGroup } -OperationName "Get Local Groups" -Quiet:$Quiet
    if ($localGroups) {
        foreach ($group in $localGroups) {
            $members = Invoke-WinFireSafeOperation -Operation { Get-LocalGroupMember -Group $group.Name | Select-Object Name, PrincipalSource } -OperationName "Get Group Members for $($group.Name)" -Quiet:$Quiet
            if ($members) {
                $groupMemberships += [PSCustomObject]@{
                    GroupName = $group.Name
                    Members   = $members | ConvertTo-Json -Compress
                }
            }
        }
        Save-WinFireData -Data $groupMemberships -FileName "Local_Group_Memberships" -Quiet:$Quiet
    }


    # Profile directories and user-specific artifacts
    $userProfiles = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_UserProfile | Select-Object -Property LocalPath, Sid, LastUseTime, Loaded
    } -OperationName "Get User Profiles" -Quiet:$Quiet

    if ($userProfiles) {
        foreach ($profile in $userProfiles) {
            $username = (New-Object System.Security.Principal.SecurityIdentifier $profile.Sid).Translate([System.Security.Principal.NTAccount]).Value
            $profilePath = $profile.LocalPath

            $recentFiles = @()
            # Attempt to find some recently accessed files (limited to desktop for Quick scan)
            $pathsToSearch = @("$profilePath\Desktop")
            if (-not $Quick) {
                $pathsToSearch += @("$profilePath\Documents", "$profilePath\Downloads")
            }

            foreach ($path in $pathsToSearch) {
                $files = Invoke-WinFireSafeOperation -Operation {
                    Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime, CreationTime | Select-Object -First 5
                } -OperationName "Scan recent files in $path for $username" -Quiet:$Quiet
                if ($files) { $recentFiles += $files }
            }

            if ($recentFiles.Count -gt 0) {
                 $userProfileArtifacts += [PSCustomObject]@{
                    Username          = $username
                    ProfilePath       = $profilePath
                    RecentlyAccessedFiles = $recentFiles | ConvertTo-Json -Compress
                }
            }
        }
        Save-WinFireData -Data $userProfileArtifacts -FileName "User_Profile_Artifacts" -Quiet:$Quiet
    }
    Get-WinFireSummaryEntry -Category "User Accounts" -Description "Collected local user accounts, group memberships, and limited profile artifacts." -Status "Success" -Details "Collected $(($localUsers | Measure-Object).Count) local users."
}

Function Get-WinFireProcessServiceAnalysis {
    <#
    .SYNOPSIS
        Collects information about running processes and services.
    #>
    param(
        [string]$HashAlgorithm,
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Process & Service Analysis" -Status "Gathering process and service details..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $processList = @()
    $serviceList = @()
    $scheduledTasks = @()
    $wmiEventSubscriptions = @()

    # Running processes
    $processes = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, @{Name='User';Expression={
            try { ($_.GetOwner().User + "\" + $_.GetOwner().Domain) } catch { "N/A" }
        }}
    } -OperationName "Collect Running Processes" -Quiet:$Quiet

    if ($processes) {
        foreach ($p in $processes) {
            $hash = "N/A"
            if ($p.ExecutablePath) {
                # Only hash if it's not a Quick scan, or if it's a known suspicious path (example: temp or user profile)
                if (-not $Quick -or ($p.ExecutablePath -like "$env:TEMP\*" -or $p.ExecutablePath -like "$env:LOCALAPPDATA\*")) {
                    $hash = Get-FileHashSafe -FilePath $p.ExecutablePath -Algorithm $HashAlgorithm
                }
            }
            $processList += [PSCustomObject]@{
                PID            = $p.ProcessId
                PPID           = $p.ParentProcessId
                Name           = $p.Name
                Path           = $p.ExecutablePath
                CommandLine    = $p.CommandLine
                CreationDate   = $p.CreationDate.ToString('yyyy-MM-dd HH:mm:ss')
                User           = $p.User
                FileHash       = $hash
            }
        }
        Save-WinFireData -Data $processList -FileName "Running_Processes" -Quiet:$Quiet
    }

    # Running and startup services
    $serviceList = Invoke-WinFireSafeOperation -Operation {
        Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType, DependentServices, RequiredServices
        # Also get BinaryPathName from Win32_Service
        $serviceDetails = Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode, State, ProcessId
        $serviceDetails
    } -OperationName "Collect Services" -Quiet:$Quiet
    Save-WinFireData -Data $serviceList -FileName "Services" -Quiet:$Quiet

    # Scheduled tasks
    $scheduledTasks = Invoke-WinFireSafeOperation -Operation {
        Get-ScheduledTask | Select-Object TaskName, State, LastRunTime, LastTaskResult, Author, @{N='Actions';E={($_.Actions | ConvertTo-Json -Compress)}}, @{N='Triggers';E={($_.Triggers | ConvertTo-Json -Compress)}}
    } -OperationName "Collect Scheduled Tasks" -Quiet:$Quiet
    Save-WinFireData -Data $scheduledTasks -FileName "Scheduled_Tasks" -Quiet:$Quiet

    # WMI Event Subscriptions (Persistence mechanism)
    $wmiEventSubscriptions = Invoke-WinFireSafeOperation -Operation {
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName '__EventConsumer'
        $filters = Get-CimInstance -Namespace root\subscription -ClassName '__EventFilter'
        $bindings = Get-CimInstance -Namespace root\subscription -ClassName '__FilterToConsumerBinding'
        $results = @()
        foreach ($binding in $bindings) {
            $consumerName = ($consumers | Where-Object { $_.__PATH -eq $binding.Consumer }).Name
            $filterQuery = ($filters | Where-Object { $_.__PATH -eq $binding.Filter }).Query
            $filterTarget = ($filters | Where-Object { $_.__PATH -eq $binding.Filter }).TargetInstanceClassName

            $results += [PSCustomObject]@{
                ConsumerName = $consumerName
                FilterQuery  = $filterQuery
                FilterTarget = $filterTarget
                BindingPath  = $binding.__PATH
            }
        }
        $results
    } -OperationName "Collect WMI Event Subscriptions" -Quiet:$Quiet
    Save-WinFireData -Data $wmiEventSubscriptions -FileName "WMI_Event_Subscriptions" -Quiet:$Quiet

    Get-WinFireSummaryEntry -Category "Process & Service" -Description "Collected running processes, services, scheduled tasks, and WMI event subscriptions." -Status "Success" -Details "Collected $(($processList | Measure-Object).Count) processes and $(($serviceList | Measure-Object).Count) services."
}

Function Get-WinFireNetworkAnalysis {
    <#
    .SYNOPSIS
        Collects network configuration and activity information.
    #>
    param(
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Network Analysis" -Status "Capturing network connections and configurations..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $activeConnections = @()
    $listeningPorts = @()
    $networkShares = @()
    $mappedDrives = @()
    $firewallRules = @()
    $promiscuousInterfaces = @()
    $smbSessions = @()
    $smbOpenFiles = @()
    $networkProfiles = @()
    $dnsEntries = @()

    $activeConnections = Invoke-WinFireSafeOperation -Operation {
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime
    } -OperationName "Get Active TCP Connections" -Quiet:$Quiet
    $activeConnections += Invoke-WinFireSafeOperation -Operation {
        Get-NetUDPConnection | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime
    } -OperationName "Get Active UDP Connections" -Quiet:$Quiet
    Save-WinFireData -Data $activeConnections -FileName "Active_Network_Connections" -Quiet:$Quiet

    $listeningPorts = $activeConnections | Where-Object {$_.State -eq 'Listen'} | Select-Object LocalAddress, LocalPort, OwningProcess -Unique
    Save-WinFireData -Data $listeningPorts -FileName "Listening_Ports" -Quiet:$Quiet

    $networkShares = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_Share | Select-Object Name, Path, Description, Type
    } -OperationName "Get Network Shares" -Quiet:$Quiet
    Save-WinFireData -Data $networkShares -FileName "Network_Shares" -Quiet:$Quiet

    $mappedDrives = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_NetworkConnection | Select-Object RemoteName, LocalName, ConnectionType, UserName
    } -OperationName "Get Mapped Network Drives" -Quiet:$Quiet
    Save-WinFireData -Data $mappedDrives -FileName "Mapped_Network_Drives" -Quiet:$Quiet

    $firewallRules = Invoke-WinFireSafeOperation -Operation {
        Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, Group, LocalAddress, RemoteAddress, LocalPort, RemotePort, Protocol, Program, Service
    } -OperationName "Get Firewall Rules" -Quiet:$Quiet
    Save-WinFireData -Data $firewallRules -FileName "Firewall_Rules" -Quiet:$Quiet

    # Network interface promiscuous mode detection (using WMI for better PowerShell integration than netsh text parsing)
    $promiscuousInterfaces = Invoke-WinFireSafeOperation -Operation {
        $networkAdapters = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } # Connected adapters
        $promiscList = @()
        foreach ($adapter in $networkAdapters) {
            # Promiscuous mode detection is complex. WMI does not expose it directly.
            # Using netsh as a simpler, though less direct, indicator.
            # Note: netsh bridge show adapter needs specific bridge name, general promiscuous check is harder.
            # This is a basic example; a more robust check involves checking specific adapter properties
            # if they exist or using tools like Get-NetAdapterAdvancedProperty.
            try {
                # This is a very basic check and might not catch all cases, but it's an attempt.
                $ifGuid = (Get-NetAdapter -Name $adapter.Name).InterfaceGuid.Guid
                $binding = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$ifGuid" -ErrorAction SilentlyContinue
                if ($binding -and $binding.PromiscuousMode -eq "1") { # Placeholder: This registry key might not exist or be accurate on all systems
                    $promiscList += [PSCustomObject]@{
                        InterfaceName = $adapter.Name
                        Description   = $adapter.Description
                        PromiscuousMode = "Likely Enabled (Registry Indicator)"
                    }
                }
            } catch {}
        }
        $promiscList
    } -OperationName "Detect Promiscuous Mode Interfaces" -Quiet:$Quiet
    Save-WinFireData -Data $promiscuousInterfaces -FileName "Promiscuous_Interfaces" -Quiet:$Quiet

    # SMB sessions and open files
    $smbSessions = Invoke-WinFireSafeOperation -Operation {
        Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
    } -OperationName "Get SMB Sessions" -Quiet:$Quiet
    Save-WinFireData -Data $smbSessions -FileName "SMB_Sessions" -Quiet:$Quiet

    $smbOpenFiles = Invoke-WinFireSafeOperation -Operation {
        Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object Path, ClientComputerName, SessionId, FileId
    } -OperationName "Get SMB Open Files" -Quiet:$Quiet
    Save-WinFireData -Data $smbOpenFiles -FileName "SMB_Open_Files" -Quiet:$Quiet

    # Network profile information
    $networkProfiles = Invoke-WinFireSafeOperation -Operation {
        Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
    } -OperationName "Get Network Profiles" -Quiet:$Quiet
    Save-WinFireData -Data $networkProfiles -FileName "Network_Profiles" -Quiet:$Quiet

    Get-WinFireSummaryEntry -Category "Network" -Description "Collected active connections, listening ports, shares, firewall rules, and network profiles." -Status "Success" -Details "Collected $(($activeConnections | Measure-Object).Count) network connections."
}

Function Get-WinFireFileSystemAnalysis {
    <#
    .SYNOPSIS
        Collects information about recently changed files and suspicious locations.
    #>
    param(
        [string]$HashAlgorithm,
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "File System Analysis" -Status "Searching for suspicious files and artifacts..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $recentFiles = @()
    $suspiciousFiles = @()
    $startupLocations = @()
    $tempFiles = @()
    $amcacheFile = @()
    $prefetchFiles = @()
    $srumDb = @()
    $windowsTimeline = @()
    $bitsJobs = @()

    $searchPaths = @(
        "$env:SystemRoot\Temp",
        "$env:TEMP",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:SystemRoot\Tasks",
        "$env:SystemRoot\System32\Tasks" # Removed trailing comma from here
        #"$env:ProgramFiles", # Potentially very large, only for full targeted scans if needed
        #"$env:ProgramFiles(x86)" # Potentially very large
    )

    $suspiciousExtensions = @("exe", "dll", "ps1", "vbs", "bat", "cmd", "hta", "js", "jse", "wsf", "lnk", "url", "scr", "ocx")
    $recentTimeThreshold = (Get-Date).AddDays(-30) # Look for files modified in the last 30 days

    foreach ($path in $searchPaths) {
        if (-not (Test-Path $path)) { continue }
        Log-WinFireMessage -Type INFO -Message "Scanning path: $path" -Quiet:$Quiet

        $items = Invoke-WinFireSafeOperation -Operation {
            Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $recentTimeThreshold -or $_.CreationTime -ge $recentTimeThreshold }
        } -OperationName "Get files from $path" -Quiet:$Quiet

        if ($items) {
            foreach ($item in $items) {
                $hash = Get-FileHashSafe -FilePath $item.FullName -Algorithm $HashAlgorithm
                $recentFiles += [PSCustomObject]@{
                    FullName      = $item.FullName
                    CreationTime  = $item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    LastWriteTime = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Size          = $item.Length
                    FileHash      = $hash
                }
                # Check for suspicious attributes/extensions
                $extWithoutDot = $item.Extension -replace '^\.', ''
                if ($suspiciousExtensions -contains $extWithoutDot -or
                    $item.Attributes -match "Hidden" -or
                    $item.Name -match "temp\.exe" -or $item.Name -match "install\.exe")
                {
                    $suspiciousFiles += [PSCustomObject]@{
                        FullName      = $item.FullName
                        CreationTime  = $item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                        LastWriteTime = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                        Size          = $item.Length
                        FileHash      = $hash
                        Reason        = "Suspicious Extension/Name/Attribute in Critical Path"
                    }
                }
            }
        }
    }

    # Startup folders
    $startupLocations += Invoke-WinFireSafeOperation -Operation {
        Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime
    } -OperationName "Get User Startup Folder Items" -Quiet:$Quiet
    $startupLocations += Invoke-WinFireSafeOperation -Operation {
        Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime
    } -OperationName "Get All Users Startup Folder Items" -Quiet:$Quiet
    Save-WinFireData -Data $startupLocations -FileName "Startup_Folder_Items" -Quiet:$Quiet

    # Basic temp files (not deep scan)
    $tempFiles = Invoke-WinFireSafeOperation -Operation {
        Get-ChildItem -Path "$env:TEMP" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { ($_.CreationTime -ge $recentTimeThreshold) -or ($_.LastWriteTime -ge $recentTimeThreshold) } | Select-Object FullName, LastWriteTime, CreationTime | Select-Object -First 100 # Limit for quickness
    } -OperationName "Get Recent Temp Files" -Quiet:$Quiet
    Save-WinFireData -Data $tempFiles -FileName "Temp_Files" -Quiet:$Quiet

    # Collect Amcache.hve (important for execution artifacts)
    $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    if (Test-Path $amcachePath) {
        $destAmcache = Join-Path $script:OutputPath "Collected_Artifacts\Amcache.hve"
        Invoke-WinFireSafeOperation -Operation {
            Copy-Item -Path $amcachePath -Destination $destAmcache -Force -ErrorAction Stop
            $hash = Get-FileHashSafe -FilePath $destAmcache -Algorithm $HashAlgorithm
            $script:CollectedFiles += [PSCustomObject]@{Path = $destAmcache; Hash = $hash; HashType = $HashAlgorithm; Type = "File"}
            $amcacheFile += [PSCustomObject]@{Source = $amcachePath; Destination = $destAmcache; Hash = $hash}
        } -OperationName "Collect Amcache.hve" -Quiet:$Quiet
    }
    Save-WinFireData -Data $amcacheFile -FileName "Collected_Amcache" -Quiet:$Quiet

    # Collect Prefetch files
    $prefetchSource = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchSource) {
        $destPrefetch = Join-Path $script:OutputPath "Collected_Artifacts\Prefetch"
        New-Item -ItemType Directory -Path $destPrefetch -ErrorAction SilentlyContinue | Out-Null
        $pfFiles = Invoke-WinFireSafeOperation -Operation {
            Get-ChildItem -Path $prefetchSource -Filter "*.pf" -ErrorAction SilentlyContinue | Copy-Item -Destination $destPrefetch -Force -PassThru
        } -OperationName "Collect Prefetch Files" -Quiet:$Quiet

        if ($pfFiles) {
            foreach ($pf in $pfFiles) {
                $hash = Get-FileHashSafe -FilePath $pf.FullName -Algorithm $HashAlgorithm
                $script:CollectedFiles += [PSCustomObject]@{Path = $pf.FullName; Hash = $hash; HashType = $HashAlgorithm; Type = "File"}
                $prefetchFiles += [PSCustomObject]@{FileName = $pf.Name; Path = $pf.FullName; Hash = $hash}
            }
        }
    }
    Save-WinFireData -Data $prefetchFiles -FileName "Collected_Prefetch_Files" -Quiet:$Quiet

    # Collect SRUM Database
    $srumPath = "$env:SystemRoot\System32\sru\SRUDB.dat"
    if (Test-Path $srumPath) {
        $destSrum = Join-Path $script:OutputPath "Collected_Artifacts\SRUDB.dat"
        Invoke-WinFireSafeOperation -Operation {
            Copy-Item -Path $srumPath -Destination $destSrum -Force -ErrorAction Stop
            $hash = Get-FileHashSafe -FilePath $destSrum -Algorithm $HashAlgorithm
            $script:CollectedFiles += [PSCustomObject]@{Path = $destSrum; Hash = $hash; HashType = $HashAlgorithm; Type = "File"}
            $srumDb += [PSCustomObject]@{Source = $srumPath; Destination = $destSrum; Hash = $hash}
        } -OperationName "Collect SRUDB.dat (SRUM)" -Quiet:$Quiet
    }
    Save-WinFireData -Data $srumDb -FileName "Collected_SRUM_DB" -Quiet:$Quiet

    # Collect Windows Timeline (ActivitiesCache.db) - per user
    $userProfiles = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_UserProfile | Select-Object -Property LocalPath, Sid
    } -OperationName "Get User Profiles for Timeline" -Quiet:$Quiet
    if ($userProfiles) {
        foreach ($profile in $userProfiles) {
            $username = (New-Object System.Security.Principal.SecurityIdentifier $profile.Sid).Translate([System.Security.Principal.NTAccount]).Value
            $timelinePath = Join-Path $profile.LocalPath "AppData\Local\Microsoft\Windows\ActivitiesCache.db"
            if (Test-Path $timelinePath) {
                $destTimelineDir = Join-Path $script:OutputPath "Collected_Artifacts\Timeline\$username"
                New-Item -ItemType Directory -Path $destTimelineDir -ErrorAction SilentlyContinue | Out-Null
                $destTimeline = Join-Path $destTimelineDir "ActivitiesCache.db"
                Invoke-WinFireSafeOperation -Operation {
                    Copy-Item -Path $timelinePath -Destination $destTimeline -Force -ErrorAction Stop
                    $hash = Get-FileHashSafe -FilePath $destTimeline -Algorithm $HashAlgorithm
                    $script:CollectedFiles += [PSCustomObject]@{Path = $destTimeline; Hash = $hash; HashType = $HashAlgorithm; Type = "File"}
                    $windowsTimeline += [PSCustomObject]@{Username = $username; Source = $timelinePath; Destination = $destTimeline; Hash = $hash}
                } -OperationName "Collect Timeline for $username" -Quiet:$Quiet
            }
        }
    }
    Save-WinFireData -Data $windowsTimeline -FileName "Collected_Windows_Timeline_DBs" -Quiet:$Quiet

    # BITS Jobs (Background Intelligent Transfer Service)
    $bitsJobs = Invoke-WinFireSafeOperation -Operation {
        Get-BitsTransfer | Select-Object DisplayName, Description, FileList, JobState, JobType, Priority, TransferProgress, CreationTime, ModifiedTime
    } -OperationName "Get BITS Transfer Jobs" -Quiet:$Quiet
    Save-WinFireData -Data $bitsJobs -FileName "BITS_Jobs" -Quiet:$Quiet

    Save-WinFireData -Data $recentFiles -FileName "Recent_Files" -Quiet:$Quiet
    Save-WinFireData -Data $suspiciousFiles -FileName "Suspicious_Files" -Quiet:$Quiet

    Get-WinFireSummaryEntry -Category "File System" -Description "Collected recent files, suspicious files/locations, startup items, Amcache, Prefetch, SRUM, Timeline, and BITS jobs." -Status "Success" -Details "Identified $(($suspiciousFiles | Measure-Object).Count) potentially suspicious files."
}

Function Get-WinFireRegistryAnalysis {
    <#
    .SYNOPSIS
        Collects key registry artifacts related to persistence, user activity, and installed software.
    #>
    param(
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Registry Analysis" -Status "Extracting key registry artifacts..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $autorunRegistry = @()
    $recentDocs = @()
    $usbHistory = @()
    $networkDriveHistory = @()
    $userAssist = @() # Very complex to parse directly, will grab raw keys if possible
    $shellBags = @() # Very complex to parse directly, will grab raw keys if possible
    $persistenceKeys = @() # Merged with autorun
    $comHijacking = @()

    # Autorun registry keys (expanded for persistence)
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", # Covers Userinit, Shell
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\SOFTWARE\Classes\exefile\shell\open\command",
        "HKLM:\SOFTWARE\Classes\mscfile\shell\open\command",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", # Not direct execution but common artifact
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
    )
    foreach ($path in $autorunPaths) {
        $items = Invoke-WinFireSafeOperation -Operation {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object -Property * | ForEach-Object {
                [PSCustomObject]@{
                    Path        = $path
                    Name        = if ($_.PSPropertySet.DefaultDisplayPropertySet.Count -gt 0) {$_.PSPropertySet.DefaultDisplayPropertySet[0]} else {"N/A"}
                    Value       = if ($_.PSPropertySet.DefaultDisplayPropertySet.Count -gt 1) {$_.PSPropertySet.DefaultDisplayPropertySet[1]} else {$_.PSPropertySet.DefaultDisplayPropertySet}
                    LastWriteTime = (Get-Item -Path $path).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') # Get key's last write time
                }
            }
        } -OperationName "Collect Registry Autorun/Persistence key: $path" -Quiet:$Quiet
        if ($items) { $autorunRegistry += $items }
    }
    Save-WinFireData -Data $autorunRegistry -FileName "Registry_Autoruns_Persistence" -Quiet:$Quiet

    # Recently accessed files (RecentDocs)
    $recentDocs = Invoke-WinFireSafeOperation -Operation {
        Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\* -ErrorAction SilentlyContinue | Select-Object PSPath, PSChildName, @{N='Data';E={
            if ($_.PSObject.Properties.Count -gt 0) {
                ($_.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' -and $_.IsSettable -eq $false } | Select-Object -ExpandProperty Value) -join ','
            } else { "N/A" }
        }}
    } -OperationName "Collect Registry RecentDocs" -Quiet:$Quiet
    Save-WinFireData -Data $recentDocs -FileName "Registry_RecentDocs" -Quiet:$Quiet

    # USB Device History
    $usbHistoryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Enum\USB",
        "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" # Portable Devices
    )
    foreach ($path in $usbHistoryPaths) {
        $items = Invoke-WinFireSafeOperation -Operation {
            Get-Item -Path $path -ErrorAction SilentlyContinue | Get-Item -Path * -ErrorAction SilentlyContinue | ForEach-Object {
                $itemPath = $_.PSPath
                $properties = Get-ItemProperty -Path $itemPath -ErrorAction SilentlyContinue | Select-Object *
                [PSCustomObject]@{
                    Path        = $itemPath
                    Properties  = $properties | ConvertTo-Json -Compress
                    LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        } -OperationName "Collect Registry USB History: $path" -Quiet:$Quiet
        if ($items) { $usbHistory += $items }
    }
    Save-WinFireData -Data $usbHistory -FileName "Registry_USB_History" -Quiet:$Quiet

    # Network Drive History (MountedDevices)
    $networkDriveHistory = Invoke-WinFireSafeOperation -Operation {
        Get-ItemProperty -Path HKLM:\SYSTEM\MountedDevices -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            [PSCustomObject]@{
                Name        = $_.PSPropertySet.DefaultDisplayPropertySet[0]
                Value       = $_.PSPropertySet.DefaultDisplayPropertySet[1]
                AllProperties = $_ | ConvertTo-Json -Compress
            }
        }
    } -OperationName "Collect Registry MountedDevices" -Quiet:$Quiet
    Save-WinFireData -Data $networkDriveHistory -FileName "Registry_Network_Drive_History" -Quiet:$Quiet

    # User Activity Tracking (UserAssist & ShellBags - very difficult to parse in pure PowerShell)
    # We will collect the raw registry keys for later analysis
    $userAssist = Invoke-WinFireSafeOperation -Operation {
        Get-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\* -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Path = $_.PSPath
                Values = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * | ConvertTo-Json -Compress)
                LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
    } -OperationName "Collect Registry UserAssist Raw" -Quiet:$Quiet
    Save-WinFireData -Data $userAssist -FileName "Registry_UserAssist_Raw" -Quiet:$Quiet

    $shellBags = Invoke-WinFireSafeOperation -Operation {
        $sb = @()
        Get-Item -Path HKCU:\Software\Microsoft\Windows\ShellNoRoam\Bags\* -ErrorAction SilentlyContinue | ForEach-Object {
            $sb += [PSCustomObject]@{
                Path = $_.PSPath
                Values = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * | ConvertTo-Json -Compress)
                LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        Get-Item -Path HKCU:\Software\Microsoft\Windows\Shell\Bags\* -ErrorAction SilentlyContinue | ForEach-Object {
            $sb += [PSCustomObject]@{
                Path = $_.PSPath
                Values = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * | ConvertTo-Json -Compress)
                LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        $sb
    } -OperationName "Collect Registry ShellBags Raw" -Quiet:$Quiet
    Save-WinFireData -Data $shellBags -FileName "Registry_ShellBags_Raw" -Quiet:$Quiet

    # COM hijacking detection (simplified - looking for InprocServer32 pointing outside system directories)
    $comHijacking = Invoke-WinFireSafeOperation -Operation {
        $results = @()
        $clsidKeys = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue
        foreach ($clsid in $clsidKeys) {
            $inprocServer = Get-ItemProperty -Path "$($clsid.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
            if ($inprocServer -and $inprocServer.'(Default)' -and
                (-not $inprocServer.'(Default)'.StartsWith($env:SystemRoot)) -and
                (-not $inprocServer.'(Default)'.StartsWith($env:ProgramFiles)) -and
                (-not $inprocServer.'(Default)'.StartsWith(${env:ProgramFiles(x86)}))) {
                $results += [PSCustomObject]@{
                    CLSID = $clsid.PSChildName
                    Path = $inprocServer.'(Default)'
                    LastWriteTime = $clsid.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
            }
        }
        $results
    } -OperationName "Detect COM Hijacking Indicators" -Quiet:$Quiet
    Save-WinFireData -Data $comHijacking -FileName "Registry_COM_Hijacking_Indicators" -Quiet:$Quiet

    Get-WinFireSummaryEntry -Category "Registry Analysis" -Description "Collected autorun keys, recent docs, USB/network history, raw user activity keys, and COM hijacking indicators." -Status "Success" -Details "Collected $(($autorunRegistry | Measure-Object).Count) autorun/persistence entries."
}

Function Get-WinFireEventLogAnalysis {
    <#
    .SYNOPSIS
        Collects critical event log entries.
    #>
    param(
        [switch]$Quick,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Event Log Analysis" -Status "Parsing critical event logs..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $collectedEvents = @()

    $logNames = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational")
    $timeSpan = if ($Quick) { (Get-Date).AddDays(-7) } else { (Get-Date).AddDays(-30) } # Last 7 or 30 days

    $securityEventIDs = @(4624, 4625, 4634, 4647, 4672, 4720, 4732, 4740, 4776, 4777, 4798, 4799, 5145, 5146, 4688) # Logon/Logoff, Privileges, Account Management, Network Share Access, Process Creation
    $systemEventIDs = @(7036, 7045, 7022, 7023, 7024, 7026, 6005, 6006, 6008) # Service Start/Stop, Service Install, Boot/Shutdown
    $appEventIDs = @(1000, 1001, 1002, 1003) # Application crashes/errors
    $powerShellEventIDs = @(4103, 4104) # Script block logging, Module logging
    $defenderEventIDs = @(1000, 1001, 1002, 1116, 1117) # Defender detections, malware activity

    foreach ($logName in $logNames) {
        $events = Invoke-WinFireSafeOperation -Operation {
            $filterHashTable = @{
                LogName   = $logName
                StartTime = $timeSpan
            }

            switch ($logName) {
                "Security" { $filterHashTable.ID = $securityEventIDs }
                "System" { $filterHashTable.ID = $systemEventIDs }
                "Application" { if ($Quick) { $filterHashTable.ID = $appEventIDs } } # Only critical for quick
                "Microsoft-Windows-PowerShell/Operational" { $filterHashTable.ID = $powerShellEventIDs }
                "Microsoft-Windows-Windows Defender/Operational" { $filterHashTable.ID = $defenderEventIDs }
            }

            # Use -MaxEvents for quick scan to limit volume
            if ($Quick) {
                Get-WinEvent -FilterHashtable $filterHashTable -ErrorAction SilentlyContinue -MaxEvents 5000
            } else {
                Get-WinEvent -FilterHashtable $filterHashTable -ErrorAction SilentlyContinue
            }
        } -OperationName "Collect events from log: $logName" -Quiet:$Quiet

        if ($events) {
            foreach ($event in $events) {
                $collectedEvents += [PSCustomObject]@{
                    LogName    = $event.LogName
                    Id         = $event.Id
                    ProviderName = $event.ProviderName
                    TimeCreated = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    LevelDisplayName = $event.LevelDisplayName
                    Message    = ($event.Message -replace "`r`n"," ").Substring(0, [System.Math]::Min(500, $event.Message.Length)) # Truncate long messages
                    Properties = $event.Properties | ForEach-Object { "$($_.Name): $($_.Value)" } | Out-String # For specific data fields
                }
            }
        }
    }

    Save-WinFireData -Data $collectedEvents -FileName "Event_Logs" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Event Logs" -Description "Collected critical Security, System, Application, PowerShell, and Windows Defender events." -Status "Success" -Details "Collected $(($collectedEvents | Measure-Object).Count) event log entries."
}

Function Get-WinFireBrowserForensics {
    <#
    .SYNOPSIS
        Collects browser history and cache files for later analysis.
    #>
    param(
        [string]$HashAlgorithm,
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Browser Forensics" -Status "Copying browser data for offline analysis..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $browserArtifacts = @()
    $browserProfilesRoot = Join-Path -Path $script:OutputPath -ChildPath "Collected_Artifacts\Browser_Profiles"
    New-Item -ItemType Directory -Path $browserProfilesRoot -ErrorAction SilentlyContinue | Out-Null

    Function Copy-LockedBrowserFiles {
        <#
        .SYNOPSIS
            Attempts to copy browser files, using RoboCopy for resilience with locked files.
        .PARAMETER SourcePath
            The source directory to copy.
        .PARAMETER DestPath
            The destination directory.
        .PARAMETER BrowserName
            Name of the browser for logging.
        #>
        param(
            [Parameter(Mandatory=$true)]
            [string]$SourcePath,
            [Parameter(Mandatory=$true)]
            [string]$DestPath,
            [string]$BrowserName
        )
        $success = $false
        try {
            # Check if browser processes are running
            $browserProcessNames = @("chrome", "firefox", "msedge")
            $runningBrowserProcesses = Get-Process -Name $browserProcessNames -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$SourcePath*" }

            if ($runningBrowserProcesses.Count -gt 0) {
                Log-WinFireMessage -Type WARN -Message "Browser processes detected for ${BrowserName}. Attempting robust copy with RoboCopy due to potential file locks." -Quiet:$Quiet
                # Use ROBOCOPY for better handling of locked files. /E (empty dirs), /COPY:DAT (data, attributes, timestamps), /R:3 (retries), /W:1 (wait time), /NJH /NJS (no job header/summary for cleaner output)
                $robocopyArgs = @("/E", "/COPY:DAT", "/R:3", "/W:1", "/NJH", "/NJS")
                $robocopyCmd = "robocopy.exe"

                $command = "$robocopyCmd `"$SourcePath`" `"$DestPath`" $($robocopyArgs -join ' ')"
                Log-WinFireMessage -Type INFO -Message "Executing: $command" -Quiet:$Quiet

                # Execute robocopy and capture output/exit code
                $proc = Start-Process -FilePath $robocopyCmd -ArgumentList @("$SourcePath", "$DestPath") + $robocopyArgs -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                $exitCode = $proc.ExitCode

                # RoboCopy success codes (0-7 usually mean success or minor issues)
                if ($exitCode -le 7) {
                    $success = $true
                    Log-WinFireMessage -Type SUCCESS -Message "RoboCopy for ${BrowserName} completed with exit code $exitCode (likely successful)." -Quiet:$Quiet
                } else {
                    Log-WinFireMessage -Type ERROR -Message "RoboCopy for ${BrowserName} failed with exit code $exitCode." -Quiet:$Quiet
                }
            } else {
                Log-WinFireMessage -Type INFO -Message "No active browser processes for ${BrowserName}. Attempting standard copy." -Quiet:$Quiet
                Copy-Item -Path $SourcePath -Destination $DestPath -Recurse -Force -ErrorAction Stop
                $success = $true
            }
        } catch {
            Log-WinFireMessage -Type ERROR -Message "Failed to copy browser files for ${BrowserName}: $_" -Quiet:$Quiet
            $success = $false
        }
        return $success
    }

    $browsers = @(
        @{Name = "Google Chrome"; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data"},
        @{Name = "Microsoft Edge"; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
        @{Name = "Mozilla Firefox"; Path = "$env:APPDATA\Mozilla\Firefox\Profiles"}
    )

    foreach ($browser in $browsers) {
        $browserPath = $browser.Path
        if (Test-Path $browserPath) {
            $destPath = Join-Path $browserProfilesRoot $($browser.Name.Replace(' ', '_'))
            $copySuccess = Copy-LockedBrowserFiles -SourcePath $browserPath -DestPath $destPath -BrowserName $browser.Name -Quiet:$Quiet
            if ($copySuccess -and (Test-Path $destPath)) {
                $browserArtifacts += [PSCustomObject]@{
                    BrowserName = $browser.Name
                    SourcePath  = $browserPath
                    CopiedTo    = $destPath
                    Status      = "Copied for external analysis"
                }
                # Hash collected directory - individual files won't be hashed here, only the directory itself
                $hash = Get-FileHashSafe -FilePath $destPath -Algorithm $HashAlgorithm # This will hash the directory content as a whole (won't work for directories with Get-FileHash directly)
                # Instead, we just record the copied path. Hashing individual files within the copied directory is too slow and redundant here.
                $script:CollectedFiles += [PSCustomObject]@{
                    Path     = $destPath
                    Hash     = "N/A (Directory Copy)"
                    HashType = $HashAlgorithm
                    Type     = "Directory"
                }
            } else {
                $browserArtifacts += [PSCustomObject]@{
                    BrowserName = $browser.Name
                    SourcePath  = $browserPath
                    CopiedTo    = "N/A"
                    Status      = "Failed/Partial copy - Check logs"
                }
            }
        } else {
            Log-WinFireMessage -Type INFO -Message "$($browser.Name) data path not found: $browserPath" -Quiet:$Quiet
            $browserArtifacts += [PSCustomObject]@{
                BrowserName = $browser.Name
                SourcePath  = $browserPath
                CopiedTo    = "N/A"
                Status      = "Path not found"
            }
        }
    }
    Save-WinFireData -Data $browserArtifacts -FileName "Browser_Artifact_Collection" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Browser Forensics" -Description "Attempted to collect browser profile data for Chrome, Edge, and Firefox (using RoboCopy for locked files)." -Status "Success" -Details "Refer to 'Collected_Artifacts\Browser_Profiles' for raw data (requires external tools for parsing)."
}

Function Get-WinFireSecurityToolsDetection {
    <#
    .SYNOPSIS
        Detects security tools (AV, EDR) status.
    #>
    param(
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Security Tools Detection" -Status "Checking AV/EDR status..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $securityToolStatus = @()

    # Windows Defender status
    $defenderStatus = Invoke-WinFireSafeOperation -Operation {
        Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, FullScanEndTime, QuickScanEndTime, SignatureLastUpdated, @{Name='ProductVersion'; Expression={ (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows Defender).ProductVersion }}
    } -OperationName "Get Windows Defender Status" -Quiet:$Quiet
    if ($defenderStatus) {
        $securityToolStatus += [PSCustomObject]@{
            Tool         = "Windows Defender"
            Status       = if ($defenderStatus.AntivirusEnabled) {"Enabled"} else {"Disabled"}
            Details      = $defenderStatus | ConvertTo-Json -Compress
        }
    } else {
        $securityToolStatus += [PSCustomObject]@{Tool = "Windows Defender"; Status = "Not Detected/Error"; Details = "Could not retrieve status."}
    }

    # Installed AntiVirus products (via WMI)
    $avProducts = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object DisplayName, ProductState, PathToSignedProductExe, @{N='Enabled';E={($_.ProductState -band 0x100000) -ne 0}}, @{N='UpToDate';E={($_.ProductState -band 0x20000) -ne 0}}
    } -OperationName "Get Installed AV Products" -Quiet:$Quiet
    if ($avProducts) {
        foreach ($av in $avProducts) {
             $securityToolStatus += [PSCustomObject]@{
                Tool         = $av.DisplayName
                Status       = if ($av.Enabled) {"Enabled"} else {"Disabled"}
                Details      = $av | ConvertTo-Json -Compress
            }
        }
    }

    # Check for common EDR/XDR service names (non-exhaustive list)
    $edrServices = @(
        "CylanceSvc", "CrowdStrike Falcon Sensor", "CarbonBlack", "MsSense", # Microsoft Defender for Endpoint
        "SentinelAgent", "Elastic Agent", "sophos auto update", "Kaspersky Lab Host Agent",
        "Symantec Endpoint Protection", "McAfee Agent", "GRCAgent", "cb.exe", "wscsvc" # Defender's AV related service
    )
    $foundEdr = @()
    foreach ($serviceName in $edrServices) {
        $service = Invoke-WinFireSafeOperation -Operation {
            Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        } -OperationName "Check EDR Service: $serviceName" -Quiet:$Quiet
        if ($service) {
            $foundEdr += [PSCustomObject]@{
                Name     = $service.Name
                DisplayName = $service.DisplayName
                Status   = $service.Status
                StartType = $service.StartType
                Path     = (Invoke-WinFireSafeOperation -Operation { (Get-CimInstance Win32_Service | Where-Object Name -eq $service.Name).PathName } -OperationName "Get Service Path for $($service.Name)" -Quiet:$Quiet)
            }
        }
    }
    if ($foundEdr.Count -gt 0) {
        $securityToolStatus += [PSCustomObject]@{
            Tool         = "EDR/XDR Agents (Detected Services)"
            Status       = "Detected"
            Details      = $foundEdr | ConvertTo-Json -Compress
        }
    } else {
        $securityToolStatus += [PSCustomObject]@{
            Tool         = "EDR/XDR Agents (Detected Services)"
            Status       = "None Found (based on common names)"
            Details      = "No common EDR service names found."
        }
    }

    Save-WinFireData -Data $securityToolStatus -FileName "Security_Tool_Status" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Security Tools" -Description "Checked status of Windows Defender and detected other AV/EDR agents." -Status "Success" -Details "Identified $(($securityToolStatus | Measure-Object).Count) security tool entries."
}

Function Get-WinFireMemoryAnalysisIndicators {
    <#
    .SYNOPSIS
        Collects basic indicators related to memory for later analysis.
        Full memory analysis requires specialized tools (e.g., Volatility).
    #>
    param(
        [switch]$Quiet
    )
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Memory Analysis Indicators" -Status "Collecting loaded modules and suspicious process details..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $loadedModules = @()
    $injectedProcesses = @()
    $suspiciousProcesses = @()
    $dllAnomalies = @()

    # Loaded Modules (DLLs) for running processes
    $processes = Invoke-WinFireSafeOperation -Operation { Get-Process } -OperationName "Get All Processes for Module Analysis" -Quiet:$Quiet
    if ($processes) {
        foreach ($p in $processes) {
            try {
                $p.Modules | ForEach-Object {
                    $loadedModules += [PSCustomObject]@{
                        ProcessName = $p.ProcessName
                        ProcessId   = $p.Id
                        ModuleName  = $_.ModuleName
                        FileName    = $_.FileName
                        BaseAddress = $_.BaseAddress
                        ModuleSize  = $_.ModuleSize
                    }
                }
            }
            catch {
                Log-WinFireMessage -Type WARN -Message "Could not get modules for process $($p.ProcessName) (PID: $($p.Id)): $_" -Quiet:$Quiet
            }
        }
        Save-WinFireData -Data $loadedModules -FileName "Loaded_Modules" -Quiet:$Quiet
    }

    # Check for process hollowing indicators (rough estimates)
    $suspiciousProcesses = Invoke-WinFireSafeOperation -Operation {
        Get-Process | Where-Object {
            # Process Name vs MainModule Name (sometimes indicative of hollowed/replaced PEB)
            # This relies on MainModule being accessible, which isn't always the case for system processes or highly restricted ones.
            ($_.MainModule.ModuleName -ne $_.ProcessName -and $_.MainModule.ModuleName -ne $null) -or
            # Unusually few modules for a typical process
            ($_.Modules.Count -lt 3 -and $_.ProcessName -notmatch "idle|system|csrss|smss") -or
            # Memory anomalies: working set much smaller than virtual memory size (might indicate unmapped sections)
            ($_.WorkingSet -lt 1MB -and $_.VirtualMemorySize -gt 100MB)
        } | Select-Object Id, ProcessName, Path, CommandLine, WorkingSet, VirtualMemorySize, @{Name='MainModule'; Expression={try{$_.MainModule.ModuleName}catch{"N/A"}}}, @{Name='ModuleCount';Expression={try{$_.Modules.Count}catch{"N/A"}}}
    } -OperationName "Detect Suspicious Processes (Hollowing Indicators)" -Quiet:$Quiet
    Save-WinFireData -Data $suspiciousProcesses -FileName "Suspicious_Process_Indicators" -Quiet:$Quiet

    # Check for DLL injection indicators (suspicious DLLs loaded from non-standard/temp paths)
    $dllAnomalies = Invoke-WinFireSafeOperation -Operation {
        $results = @()
        Get-Process | ForEach-Object {
            $process = $_
            $systemPaths = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})
            try {
                $process.Modules | Where-Object {
                    $_.FileName -and
                    ($systemPaths | ForEach-Object { "$($_.TrimEnd('\'))\" }) -notcontains ($_.FileName | Split-Path -Parent | Select-Object -First 1) -and # Not in system or program files
                    ($_.FileName -like "*temp\*" -or $_.FileName -like "*appdata\*") # Loaded from temp or appdata
                } | ForEach-Object {
                    $results += [PSCustomObject]@{
                        ProcessName = $process.ProcessName
                        PID = $process.Id
                        SuspiciousDLL = $_.FileName
                        BaseAddress = $_.BaseAddress
                    }
                }
            } catch {
                Log-WinFireMessage -Type WARN -Message "Could not check DLLs for process $($process.ProcessName) (PID: $($process.Id)): $_" -Quiet:$Quiet
            }
        }
        $results
    } -OperationName "Detect DLL Injection Indicators" -Quiet:$Quiet
    Save-WinFireData -Data $dllAnomalies -FileName "DLL_Injection_Indicators" -Quiet:$Quiet

    Save-WinFireData -Data $injectedProcesses -FileName "Processes_No_MainWindow" -Quiet:$Quiet # A very crude indicator
    Get-WinFireSummaryEntry -Category "Memory Indicators" -Description "Collected loaded DLLs, process hollowing indicators, and DLL injection indicators." -Status "Success" -Details "Full memory analysis requires external tools like Volatility."
}

Function Get-WinFirePowerShellActivity {
    <#
    .SYNOPSIS
        Collects PowerShell logging configuration to detect evasion attempts.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "PowerShell Activity Analysis" -Status "Checking PowerShell logging configuration..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $psLoggingConfig = @()

    # Script Block Logging
    $scriptBlockLogging = Invoke-WinFireSafeOperation -Operation {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    } -OperationName "Get PowerShell Script Block Logging Config" -Quiet:$Quiet
    $psLoggingConfig += [PSCustomObject]@{
        Setting = "Script Block Logging"
        Enabled = if ($scriptBlockLogging -and $scriptBlockLogging.EnableScriptBlockLogging) { $true } else { $false }
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    }

    # Module Logging
    $moduleLogging = Invoke-WinFireSafeOperation -Operation {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    } -OperationName "Get PowerShell Module Logging Config" -Quiet:$Quiet
    $psLoggingConfig += [PSCustomObject]@{
        Setting = "Module Logging"
        Enabled = if ($moduleLogging -and $moduleLogging.EnableModuleLogging) { $true } else { $false }
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    }

    # Transcription
    $transcription = Invoke-WinFireSafeOperation -Operation {
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
    } -OperationName "Get PowerShell Transcription Config" -Quiet:$Quiet
    $psLoggingConfig += [PSCustomObject]@{
        Setting = "Transcription"
        Enabled = if ($transcription -and $transcription.EnableTranscripting) { $true } else { $false }
        OutputDirectory = $transcription.OutputDirectory
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    }

    Save-WinFireData -Data $psLoggingConfig -FileName "PowerShell_Logging_Configuration" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "PowerShell Activity" -Description "Collected PowerShell logging configurations (Script Block, Module, Transcription)." -Status "Success" -Details "Check for disabled logging which may indicate evasion."
}

Function Get-WinFireDefenderExclusions {
    <#
    .SYNOPSIS
        Collects Windows Defender exclusions which could hide malware.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Defender Exclusions Analysis" -Status "Checking for suspicious Defender exclusions..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $defenderExclusions = @()

    # Path exclusions
    $pathExclusions = Invoke-WinFireSafeOperation -Operation {
        (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
    } -OperationName "Get Defender Path Exclusions" -Quiet:$Quiet
    if ($pathExclusions) {
        foreach ($path in $pathExclusions) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            if ($path -like "*\Temp\*" -or $path -like "*\AppData\*" -or $path -like "*\Downloads\*") {
                $isSuspicious = $true
                $suspiciousReasons += "Located in user-writable directory"
            }
            $defenderExclusions += [PSCustomObject]@{
                Type = "Path"
                Value = $path
                IsSuspicious = $isSuspicious
                Reason = ($suspiciousReasons -join "; ")
            }
        }
    }

    # Process exclusions
    $processExclusions = Invoke-WinFireSafeOperation -Operation {
        (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionProcess
    } -OperationName "Get Defender Process Exclusions" -Quiet:$Quiet
    if ($processExclusions) {
        foreach ($proc in $processExclusions) {
            $defenderExclusions += [PSCustomObject]@{
                Type = "Process"
                Value = $proc
                IsSuspicious = $false
                Reason = ""
            }
        }
    }

    # Extension exclusions
    $extExclusions = Invoke-WinFireSafeOperation -Operation {
        (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionExtension
    } -OperationName "Get Defender Extension Exclusions" -Quiet:$Quiet
    if ($extExclusions) {
        $dangerousExtensions = @("exe", "dll", "ps1", "bat", "cmd", "vbs", "js")
        foreach ($ext in $extExclusions) {
            $isSuspicious = $false
            if ($dangerousExtensions -contains $ext.TrimStart('.')) {
                $isSuspicious = $true
            }
            $defenderExclusions += [PSCustomObject]@{
                Type = "Extension"
                Value = $ext
                IsSuspicious = $isSuspicious
                Reason = if ($isSuspicious) { "Dangerous executable extension excluded" } else { "" }
            }
        }
    }

    Save-WinFireData -Data $defenderExclusions -FileName "Defender_Exclusions" -Quiet:$Quiet
    $suspiciousCount = ($defenderExclusions | Where-Object { $_.IsSuspicious }).Count
    Get-WinFireSummaryEntry -Category "Defender Exclusions" -Description "Collected Windows Defender exclusions." -Status $(if ($suspiciousCount -gt 0) { "Warning" } else { "Success" }) -Details "Found $($defenderExclusions.Count) exclusions, $suspiciousCount suspicious."
}

Function Get-WinFirePowerShellHistory {
    <#
    .SYNOPSIS
        Collects PowerShell command history for all users.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "PowerShell History Collection" -Status "Collecting PowerShell command history..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $psHistory = @()

    # Get user profiles
    $userProfiles = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | Select-Object -Property LocalPath, SID
    } -OperationName "Get User Profiles for PS History" -Quiet:$Quiet

    if ($userProfiles) {
        foreach ($profile in $userProfiles) {
            $historyPath = Join-Path $profile.LocalPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
            if (Test-Path $historyPath) {
                $username = try { (New-Object System.Security.Principal.SecurityIdentifier $profile.SID).Translate([System.Security.Principal.NTAccount]).Value } catch { $profile.SID }
                $historyContent = Invoke-WinFireSafeOperation -Operation {
                    Get-Content -Path $historyPath -ErrorAction SilentlyContinue -Tail 500
                } -OperationName "Read PS History for $username" -Quiet:$Quiet

                if ($historyContent) {
                    $lineNum = 0
                    foreach ($line in $historyContent) {
                        $lineNum++
                        $isSuspicious = $false
                        $suspiciousPatterns = @(
                            "Invoke-Expression", "IEX", "DownloadString", "DownloadFile",
                            "FromBase64String", "EncodedCommand", "bypass", "hidden",
                            "Invoke-Mimikatz", "Invoke-WebRequest", "certutil", "bitsadmin"
                        )
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($line -match $pattern) {
                                $isSuspicious = $true
                                break
                            }
                        }
                        $psHistory += [PSCustomObject]@{
                            Username = $username
                            LineNumber = $lineNum
                            Command = $line
                            IsSuspicious = $isSuspicious
                        }
                    }

                    # Copy the history file
                    $destDir = Join-Path $script:OutputPath "Collected_Artifacts\PowerShell_History"
                    New-Item -ItemType Directory -Path $destDir -ErrorAction SilentlyContinue | Out-Null
                    $safeUsername = $username -replace '[\\/:*?"<>|]', '_'
                    $destFile = Join-Path $destDir "${safeUsername}_ConsoleHost_history.txt"
                    Copy-Item -Path $historyPath -Destination $destFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Save-WinFireData -Data $psHistory -FileName "PowerShell_History" -Quiet:$Quiet
    $suspiciousCount = ($psHistory | Where-Object { $_.IsSuspicious }).Count
    Get-WinFireSummaryEntry -Category "PowerShell History" -Description "Collected PowerShell command history from all users." -Status $(if ($suspiciousCount -gt 0) { "Warning" } else { "Success" }) -Details "Collected $($psHistory.Count) commands, $suspiciousCount flagged as suspicious."
}

Function Get-WinFireRDPAnalysis {
    <#
    .SYNOPSIS
        Analyzes RDP connections for lateral movement detection.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "RDP Analysis" -Status "Analyzing RDP sessions and connection history..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $rdpData = @()

    # Current RDP sessions
    $currentSessions = Invoke-WinFireSafeOperation -Operation {
        qwinsta 2>$null | ForEach-Object {
            if ($_ -match "rdp-tcp") {
                [PSCustomObject]@{
                    SessionInfo = $_
                    Type = "Active RDP Session"
                }
            }
        }
    } -OperationName "Get Current RDP Sessions" -Quiet:$Quiet
    if ($currentSessions) { $rdpData += $currentSessions }

    # RDP connection history from registry (outbound connections)
    $rdpServers = Invoke-WinFireSafeOperation -Operation {
        $servers = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers\*" -ErrorAction SilentlyContinue
        $servers | ForEach-Object {
            [PSCustomObject]@{
                Server = $_.PSChildName
                Username = $_.UsernameHint
                Type = "Outbound RDP History"
            }
        }
    } -OperationName "Get RDP Server History" -Quiet:$Quiet
    if ($rdpServers) { $rdpData += $rdpServers }

    # RDP events from Security log (inbound connections - Event ID 4624 with Logon Type 10)
    $rdpEvents = Invoke-WinFireSafeOperation -Operation {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties[8].Value -eq 10  # Logon Type 10 = Remote Interactive (RDP)
        }
        $events | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                SourceIP = $_.Properties[18].Value
                Username = "$($_.Properties[6].Value)\$($_.Properties[5].Value)"
                Type = "Inbound RDP Connection"
            }
        }
    } -OperationName "Get RDP Event Logs" -Quiet:$Quiet
    if ($rdpEvents) { $rdpData += $rdpEvents }

    Save-WinFireData -Data $rdpData -FileName "RDP_Analysis" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "RDP Analysis" -Description "Analyzed RDP sessions and connection history for lateral movement." -Status "Success" -Details "Collected $(($rdpData | Measure-Object).Count) RDP-related entries."
}

Function Get-WinFireLOLBASDetection {
    <#
    .SYNOPSIS
        Detects potential Living-Off-The-Land Binary (LOLBAS) abuse.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "LOLBAS Detection" -Status "Scanning for LOLBAS abuse patterns..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $lolbasFindings = @()

    # Define LOLBAS patterns
    $lolbasPatterns = @{
        "certutil.exe" = @("-urlcache", "-decode", "-encode", "-decodehex", "-f http", "-f ftp")
        "mshta.exe" = @("javascript:", "vbscript:", "http://", "https://")
        "regsvr32.exe" = @("/s /n /u /i:http", "/s /n /u /i:https", "scrobj.dll")
        "wmic.exe" = @("process call create", "os get", "/node:", "/format:http")
        "cscript.exe" = @("//e:jscript", "//e:vbscript", "http://", "https://")
        "wscript.exe" = @("//e:jscript", "//e:vbscript")
        "msiexec.exe" = @("/q http://", "/q https://", "/q \\\\")
        "bitsadmin.exe" = @("/transfer", "/download", "http://", "https://")
        "powershell.exe" = @("-enc", "-encodedcommand", "downloadstring", "downloadfile", "invoke-expression", "iex", "-nop -w hidden")
        "cmd.exe" = @("/c powershell", "/c certutil", "/c bitsadmin", "/c mshta")
        "rundll32.exe" = @("javascript:", "http://", "https://", "shell32.dll,ShellExec_RunDLL")
        "regasm.exe" = @("/u", "http://")
        "regsvcs.exe" = @("http://", "https://")
        "msbuild.exe" = @("http://", "https://")
        "installutil.exe" = @("/logfile=", "/logtoconsole=false")
    }

    # Check running processes for LOLBAS patterns
    $processes = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ParentProcessId
    } -OperationName "Get Processes for LOLBAS Check" -Quiet:$Quiet

    if ($processes) {
        foreach ($proc in $processes) {
            if ($proc.Name -and $lolbasPatterns.ContainsKey($proc.Name.ToLower())) {
                $patterns = $lolbasPatterns[$proc.Name.ToLower()]
                foreach ($pattern in $patterns) {
                    if ($proc.CommandLine -and $proc.CommandLine -match [regex]::Escape($pattern)) {
                        $parentProc = $processes | Where-Object { $_.ProcessId -eq $proc.ParentProcessId } | Select-Object -First 1
                        $lolbasFindings += [PSCustomObject]@{
                            ProcessName = $proc.Name
                            ProcessId = $proc.ProcessId
                            CommandLine = $proc.CommandLine
                            MatchedPattern = $pattern
                            ParentProcess = if ($parentProc) { "$($parentProc.Name) (PID: $($parentProc.ProcessId))" } else { "Unknown" }
                            Severity = "High"
                            Description = "Potential LOLBAS abuse detected"
                        }
                        break
                    }
                }
            }
        }
    }

    Save-WinFireData -Data $lolbasFindings -FileName "LOLBAS_Detection" -Quiet:$Quiet
    $highSeverityCount = ($lolbasFindings | Where-Object { $_.Severity -eq "High" }).Count
    Get-WinFireSummaryEntry -Category "LOLBAS Detection" -Description "Scanned for Living-Off-The-Land Binary abuse." -Status $(if ($highSeverityCount -gt 0) { "Warning" } else { "Success" }) -Details "Found $($lolbasFindings.Count) potential LOLBAS abuse patterns."
}

Function Get-WinFireCredentialIndicators {
    <#
    .SYNOPSIS
        Detects indicators of credential harvesting or dumping.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Credential Indicator Detection" -Status "Scanning for credential harvesting indicators..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $credIndicators = @()

    # Check for LSASS access (Security Event 4656/4663 with lsass.exe)
    $lsassEvents = Invoke-WinFireSafeOperation -Operation {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(4656, 4663)
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match "lsass\.exe"
        } | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                EventId = $_.Id
                Type = "LSASS Access Event"
                Details = "Potential credential dumping attempt"
                Severity = "Critical"
            }
        }
    } -OperationName "Check LSASS Access Events" -Quiet:$Quiet
    if ($lsassEvents) { $credIndicators += $lsassEvents }

    # Check for known credential dumping tools
    $credDumpTools = @("mimikatz", "procdump", "sqldumper", "comsvcs.dll", "credssp", "sekurlsa", "lsadump", "lazagne", "pypykatz")
    $processes = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath
    } -OperationName "Get Processes for Cred Tool Check" -Quiet:$Quiet

    if ($processes) {
        foreach ($proc in $processes) {
            foreach ($tool in $credDumpTools) {
                if (($proc.Name -and $proc.Name -match $tool) -or 
                    ($proc.CommandLine -and $proc.CommandLine -match $tool) -or
                    ($proc.ExecutablePath -and $proc.ExecutablePath -match $tool)) {
                    $credIndicators += [PSCustomObject]@{
                        TimeCreated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        Type = "Credential Tool Detected"
                        ToolPattern = $tool
                        ProcessName = $proc.Name
                        ProcessId = $proc.ProcessId
                        CommandLine = $proc.CommandLine
                        Severity = "Critical"
                    }
                }
            }
        }
    }

    # Check for SAM/SECURITY/SYSTEM hive copies
    $hiveCopies = Invoke-WinFireSafeOperation -Operation {
        Get-ChildItem -Path @("$env:TEMP", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop") -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^(SAM|SECURITY|SYSTEM|NTDS\.dit)$" -and $_.Length -gt 0 } |
        ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                Type = "Registry Hive Copy"
                FilePath = $_.FullName
                FileName = $_.Name
                Size = $_.Length
                Severity = "Critical"
            }
        }
    } -OperationName "Check for Hive Copies" -Quiet:$Quiet
    if ($hiveCopies) { $credIndicators += $hiveCopies }

    Save-WinFireData -Data $credIndicators -FileName "Credential_Indicators" -Quiet:$Quiet
    $criticalCount = ($credIndicators | Where-Object { $_.Severity -eq "Critical" }).Count
    Get-WinFireSummaryEntry -Category "Credential Indicators" -Description "Scanned for credential harvesting and dumping indicators." -Status $(if ($criticalCount -gt 0) { "Warning" } else { "Success" }) -Details "Found $($credIndicators.Count) indicators, $criticalCount critical."
}

Function Get-WinFireAdvancedProcessAnalysis {
    <#
    .SYNOPSIS
        Performs advanced process analysis for suspicious behaviors.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Advanced Process Analysis" -Status "Analyzing process relationships and behaviors..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $processAnalysis = @()

    # Get all processes with parent information
    $allProcesses = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate
    } -OperationName "Get All Processes for Analysis" -Quiet:$Quiet

    if ($allProcesses) {
        # Suspicious parent-child relationships
        $suspiciousRelationships = @{
            "winword.exe" = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
            "excel.exe" = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
            "outlook.exe" = @("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
            "svchost.exe" = @("powershell.exe", "cmd.exe")
            "wmiprvse.exe" = @("powershell.exe", "cmd.exe")
            "explorer.exe" = @()  # Explorer can spawn many things, but track anyway
            "services.exe" = @("cmd.exe", "powershell.exe")
        }

        foreach ($proc in $allProcesses) {
            $parentProc = $allProcesses | Where-Object { $_.ProcessId -eq $proc.ParentProcessId } | Select-Object -First 1
            if ($parentProc) {
                $parentName = $parentProc.Name.ToLower()
                $childName = $proc.Name.ToLower()

                if ($suspiciousRelationships.ContainsKey($parentName)) {
                    $suspiciousChildren = $suspiciousRelationships[$parentName]
                    if ($suspiciousChildren -contains $childName) {
                        $processAnalysis += [PSCustomObject]@{
                            ParentProcess = $parentProc.Name
                            ParentPID = $parentProc.ProcessId
                            ChildProcess = $proc.Name
                            ChildPID = $proc.ProcessId
                            ChildCommandLine = $proc.CommandLine
                            CreationTime = if ($proc.CreationDate) { $proc.CreationDate.ToString('yyyy-MM-dd HH:mm:ss') } else { "N/A" }
                            Finding = "Suspicious parent-child relationship"
                            Severity = "High"
                        }
                    }
                }
            }

            # Detect processes running from suspicious locations
            if ($proc.ExecutablePath) {
                $suspiciousLocations = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp", "C:\Users\Public", "C:\ProgramData")
                foreach ($loc in $suspiciousLocations) {
                    if ($proc.ExecutablePath -like "$loc\*") {
                        $processAnalysis += [PSCustomObject]@{
                            ParentProcess = if ($parentProc) { $parentProc.Name } else { "Unknown" }
                            ParentPID = $proc.ParentProcessId
                            ChildProcess = $proc.Name
                            ChildPID = $proc.ProcessId
                            ChildCommandLine = $proc.CommandLine
                            ExecutablePath = $proc.ExecutablePath
                            Finding = "Process running from suspicious location"
                            Severity = "Medium"
                        }
                        break
                    }
                }
            }
        }
    }

    Save-WinFireData -Data $processAnalysis -FileName "Advanced_Process_Analysis" -Quiet:$Quiet
    $highSeverityCount = ($processAnalysis | Where-Object { $_.Severity -eq "High" }).Count
    Get-WinFireSummaryEntry -Category "Advanced Process Analysis" -Description "Analyzed process trees and behaviors for suspicious patterns." -Status $(if ($highSeverityCount -gt 0) { "Warning" } else { "Success" }) -Details "Found $($processAnalysis.Count) findings, $highSeverityCount high severity."
}

Function Get-WinFireThreatScore {
    <#
    .SYNOPSIS
        Calculates an overall threat score for the system.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Threat Score Calculation" -Status "Calculating system threat score..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks

    $threatScore = 0
    $findings = @()

    # Review summary report for issues
    foreach ($entry in $script:SummaryReport) {
        switch ($entry.Status) {
            "Warning" {
                $threatScore += 5
                $findings += [PSCustomObject]@{
                    Category = $entry.Category
                    Status = $entry.Status
                    Impact = "+5 points"
                    Description = $entry.Description
                }
            }
            "Failed" {
                $threatScore += 10
                $findings += [PSCustomObject]@{
                    Category = $entry.Category
                    Status = $entry.Status
                    Impact = "+10 points"
                    Description = $entry.Description
                }
            }
        }
    }

    # Cap score at 100
    if ($threatScore -gt 100) { $threatScore = 100 }

    # Determine risk level
    $riskLevel = switch ($threatScore) {
        { $_ -le 10 } { "Low" }
        { $_ -le 30 } { "Medium" }
        { $_ -le 60 } { "High" }
        default { "Critical" }
    }

    $threatScoreResult = [PSCustomObject]@{
        ThreatScore = $threatScore
        RiskLevel = $riskLevel
        TotalFindings = $findings.Count
        CalculatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Findings = $findings | ConvertTo-Json -Compress
    }

    Save-WinFireData -Data @($threatScoreResult) -FileName "Threat_Score" -Quiet:$Quiet
    $status = switch ($riskLevel) {
        "Low" { "Success" }
        "Medium" { "Info" }
        "High" { "Warning" }
        "Critical" { "Failed" }
    }
    Get-WinFireSummaryEntry -Category "Threat Score" -Description "Calculated overall system threat score." -Status $status -Details "Score: $threatScore/100 - Risk Level: $riskLevel"

    return $threatScoreResult
}

Function Get-WinFireJumpListAnalysis {
    <#
    .SYNOPSIS
        Collects Jump List data for user activity analysis.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Jump List Analysis" -Status "Collecting Jump List data..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $jumpListData = @()

    $userProfiles = Invoke-WinFireSafeOperation -Operation {
        Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | Select-Object -Property LocalPath, SID
    } -OperationName "Get User Profiles for Jump Lists" -Quiet:$Quiet

    if ($userProfiles) {
        foreach ($profile in $userProfiles) {
            $username = try { (New-Object System.Security.Principal.SecurityIdentifier $profile.SID).Translate([System.Security.Principal.NTAccount]).Value } catch { $profile.SID }
            
            # Automatic destinations (recent/frequent)
            $autoDestPath = Join-Path $profile.LocalPath "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
            if (Test-Path $autoDestPath) {
                $jumpFiles = Invoke-WinFireSafeOperation -Operation {
                    Get-ChildItem -Path $autoDestPath -Filter "*.automaticDestinations-ms" -ErrorAction SilentlyContinue |
                    Select-Object Name, FullName, LastWriteTime, Length
                } -OperationName "Get Jump Lists for $username" -Quiet:$Quiet

                if ($jumpFiles) {
                    foreach ($jf in $jumpFiles) {
                        $jumpListData += [PSCustomObject]@{
                            Username = $username
                            Type = "AutomaticDestinations"
                            FileName = $jf.Name
                            FullPath = $jf.FullName
                            LastModified = $jf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            Size = $jf.Length
                        }
                    }

                    # Copy jump list files for external analysis
                    $destDir = Join-Path $script:OutputPath "Collected_Artifacts\JumpLists\$($username -replace '[\\/:*?""<>|]', '_')"
                    New-Item -ItemType Directory -Path $destDir -ErrorAction SilentlyContinue | Out-Null
                    Copy-Item -Path "$autoDestPath\*" -Destination $destDir -Force -ErrorAction SilentlyContinue
                }
            }

            # Custom destinations (pinned)
            $customDestPath = Join-Path $profile.LocalPath "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
            if (Test-Path $customDestPath) {
                $customFiles = Invoke-WinFireSafeOperation -Operation {
                    Get-ChildItem -Path $customDestPath -Filter "*.customDestinations-ms" -ErrorAction SilentlyContinue |
                    Select-Object Name, FullName, LastWriteTime, Length
                } -OperationName "Get Custom Jump Lists for $username" -Quiet:$Quiet

                if ($customFiles) {
                    foreach ($cf in $customFiles) {
                        $jumpListData += [PSCustomObject]@{
                            Username = $username
                            Type = "CustomDestinations"
                            FileName = $cf.Name
                            FullPath = $cf.FullName
                            LastModified = $cf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            Size = $cf.Length
                        }
                    }
                }
            }
        }
    }

    Save-WinFireData -Data $jumpListData -FileName "JumpList_Analysis" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Jump List Analysis" -Description "Collected Jump List data for user activity analysis." -Status "Success" -Details "Found $($jumpListData.Count) Jump List files."
}

Function Get-WinFireLNKAnalysis {
    <#
    .SYNOPSIS
        Analyzes LNK (shortcut) files for suspicious indicators.
    #>
    param([switch]$Quiet)
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "LNK File Analysis" -Status "Analyzing shortcut files..." -CurrentValue $script:ProgressCounter -MaxValue $script:TotalTasks
    $lnkData = @()

    $searchPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:USERPROFILE\Desktop"
    )

    $shell = New-Object -ComObject WScript.Shell

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $lnkFiles = Invoke-WinFireSafeOperation -Operation {
                Get-ChildItem -Path $searchPath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            } -OperationName "Get LNK files from $searchPath" -Quiet:$Quiet

            if ($lnkFiles) {
                foreach ($lnk in $lnkFiles) {
                    try {
                        $shortcut = $shell.CreateShortcut($lnk.FullName)
                        $isSuspicious = $false
                        $suspiciousReasons = @()

                        # Check for suspicious targets
                        if ($shortcut.TargetPath -match "(powershell|cmd|wscript|cscript|mshta|certutil)\.exe") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Points to script interpreter"
                        }
                        if ($shortcut.Arguments -match "(http|ftp|\\\\)") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Arguments contain network paths"
                        }
                        if ($shortcut.TargetPath -like "$env:TEMP\*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Target in Temp directory"
                        }

                        $lnkData += [PSCustomObject]@{
                            FileName = $lnk.Name
                            FullPath = $lnk.FullName
                            TargetPath = $shortcut.TargetPath
                            Arguments = $shortcut.Arguments
                            WorkingDirectory = $shortcut.WorkingDirectory
                            Description = $shortcut.Description
                            CreationTime = $lnk.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                            LastModified = $lnk.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = ($suspiciousReasons -join "; ")
                        }
                    }
                    catch {
                        Log-WinFireMessage -Type WARN -Message "Could not parse LNK file: $($lnk.FullName)" -Quiet:$Quiet
                    }
                }
            }
        }
    }

    # Release COM object
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null

    Save-WinFireData -Data $lnkData -FileName "LNK_Analysis" -Quiet:$Quiet
    $suspiciousCount = ($lnkData | Where-Object { $_.IsSuspicious }).Count
    Get-WinFireSummaryEntry -Category "LNK Analysis" -Description "Analyzed shortcut files for suspicious indicators." -Status $(if ($suspiciousCount -gt 0) { "Warning" } else { "Success" }) -Details "Analyzed $($lnkData.Count) LNK files, $suspiciousCount suspicious."
}

#endregion

#region Reporting and Packaging Functions

Function New-WinFireHtmlReport {
    <#
    .SYNOPSIS
        Generates a summary HTML report from collected findings.
    .PARAMETER SummaryData
        The array of summary objects.
    .PARAMETER OutputPath
        The base output path.
    .PARAMETER ChainOfCustody
        The chain of custody object.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $SummaryData,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$true)]
        $ChainOfCustody
    )
    $reportPath = Join-Path -Path $OutputPath -ChildPath "Reports\WinFire_Executive_Summary.html"
    $endTime = Get-Date
    $duration = ($endTime - $ChainOfCustody.ScanStartTime).ToString("hh\:mm\:ss")

    $htmlHeader = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WinFire Forensic Report - $($ChainOfCustody.ComputerName)</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }
            .container { max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); }
            h1, h2, h3 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 30px; }
            h1 { font-size: 2.2em; text-align: center; color: #e74c3c; }
            h2 { font-size: 1.8em; }
            h3 { font-size: 1.4em; color: #34495e; }
            .meta-info table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            .meta-info th, .meta-info td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            .meta-info th { background-color: #ecf0f1; color: #2c3e50; width: 200px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px 15px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #3498db; color: white; font-weight: bold; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .status-success { color: #27ae60; font-weight: bold; }
            .status-failed { color: #e74c3c; font-weight: bold; }
            .status-warning { color: #f39c12; font-weight: bold; }
            .status-info { color: #3498db; font-weight: bold; }
            .status-skipped { color: #7f8c8d; font-weight: bold; }
            .data-link { font-weight: bold; }
            .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #7f8c8d; font-size: 0.9em; }
            pre { background-color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>WinFire Forensic Incident Response Report</h1>
            <div class="meta-info">
                <h2>Report Overview</h2>
                <table>
                    <tr><th>System Name:</th><td>$($ChainOfCustody.ComputerName)</td></tr>
                    <tr><th>Generated By:</th><td>$($ChainOfCustody.UserName)</td></tr>
                    <tr><th>Report Date:</th><td>$endTime.ToString("yyyy-MM-dd HH:mm:ss")</td></tr>
                    <tr><th>Scan Start Time:</th><td>$($ChainOfCustody.ScanStartTime)</td></tr>
                    <tr><th>Scan End Time:</th><td>$endTime.ToString("yyyy-MM-dd HH:mm:ss")</td></tr>
                    <tr><th>Scan Duration:</th><td>$duration</td></tr>
                    <tr><th>Output Directory:</th><td>$($ChainOfCustody.OutputDirectory)</td></tr>
                    <tr><th>Case Number:</th><td>$($ChainOfCustody.CaseNumber)</td></tr>
                    <tr><th>Investigator:</th><td>$($ChainOfCustody.Investigator)</td></tr>
                    <tr><th>Purpose:</th><td>$($ChainOfCustody.Purpose)</td></tr>
                    <tr><th>System Uptime:</th><td>$($ChainOfCustody.SystemUptime)</td></tr>
                    <tr><th>NtOsKrnl.exe Hash (SHA256):</th><td>$($ChainOfCustody.NtOsKrnlHash)</td></tr>
                </table>
            </div>

            <h2>Executive Summary of Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Description</th>
                        <th>Status</th>
                        <th>Details/Summary</th>
                    </tr>
                </thead>
                <tbody>
"@

    $htmlBody = ""
    foreach ($entry in $SummaryData) {
        $statusClass = ""
        switch ($entry.Status) {
            "Success" { $statusClass = "status-success" }
            "Failed"  { $statusClass = "status-failed" }
            "Warning" { $statusClass = "status-warning" }
            "Info"    { $statusClass = "status-info" }
            "Skipped" { $statusClass = "status-skipped" }
            default   { $statusClass = "" }
        }
        $htmlBody += "<tr>"
        $htmlBody += "<td>$($entry.Category)</td>"
        $htmlBody += "<td>$($entry.Description)</td>"
        $htmlBody += "<td class='$statusClass'>$($entry.Status)</td>"
        $htmlBody += "<td>$($entry.Details)</td>"
        $htmlBody += "</tr>"
    }

    $htmlFooter = @"
                </tbody>
            </table>

            <h2>Collected Data Locations</h2>
            <p>Detailed forensic artifacts are saved in the following subdirectories:</p>
            <ul>
                <li><strong>Raw_Data:</strong> Contains CSV and JSON files for each collected data category.</li>
                <li><strong>Collected_Artifacts:</strong> Contains raw copies of specific artifacts (e.g., browser profiles, Amcache.hve, Prefetch, SRUM, Timeline).</li>
                <li><strong>Reports:</strong> Contains this HTML summary, the Hash Manifest, and Chain of Custody (JSON).</li>
                <li><strong>WinFire_ExecutionLog.txt:</strong> Detailed log of script execution, warnings, and errors.</li>
            </ul>

            <h3>Chain of Custody & Evidence Integrity</h3>
            <p>A <code>Chain_Of_Custody.json</code> file is generated in the <code>Reports</code> directory, documenting key details of the scan.</p>
            <p>The <code>WinFire_ExecutionLog.txt</code> also acts as a chain of custody log, recording execution details, timestamps, and any errors encountered during the scan.</p>
            <p>A hash manifest (<code>Hash_Manifest.txt</code>) is generated in the <code>Reports</code> directory, containing cryptographic hashes for all individually collected and copied files, ensuring their integrity.</p>

            <div class="footer">
                <p>WinFire (Windows Forensic Incident Response Engine) - Version $($ChainOfCustody.WinFireVersion)</p>
                <p>Generated on $($ChainOfCustody.ComputerName) at $endTime.ToString("yyyy-MM-dd HH:mm:ss")</p>
                <p>Disclaimer: This tool is for incident response and digital forensics purposes. Always verify findings with additional tools and methods.</p>
            </div>
        </div>
    </body>
    </html>
"@

    $htmlContent = $htmlHeader + $htmlBody + $htmlFooter

    Invoke-WinFireSafeOperation -Operation {
        Set-Content -Path $reportPath -Value $htmlContent -Encoding UTF8 -Force -ErrorAction Stop
    } -OperationName "Generate HTML Report" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Report Generation" -Description "Executive Summary Report generated." -Status "Success" -Details "File: WinFire_Executive_Summary.html"
}

Function New-WinFireHashManifest {
    <#
    .SYNOPSIS
        Generates a hash manifest for all collected files.
    .PARAMETER CollectedFiles
        Array of custom objects containing file path, hash, and hash type.
    .PARAMETER OutputPath
        The base output path.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $CollectedFiles,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    $manifestPath = Join-Path -Path $OutputPath -ChildPath "Reports\Hash_Manifest.txt"
    $manifestContent = @()
    $manifestContent += "--- WinFire Hash Manifest ---"
    $manifestContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $manifestContent += "Algorithm Used: $($script:GlobalHashAlgorithm)"
    $manifestContent += "-----------------------------"
    $manifestContent += ""

    foreach ($file in $CollectedFiles) {
        $manifestContent += "$($file.HashType): $($file.Hash) | Type: $($file.Type) | Path: $($file.Path)"
    }

    Invoke-WinFireSafeOperation -Operation {
        Set-Content -Path $manifestPath -Value ($manifestContent -join "`n") -Encoding UTF8 -Force -ErrorAction Stop
    } -OperationName "Generate Hash Manifest" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Evidence Integrity" -Description "Hash Manifest generated for collected files." -Status "Success" -Details "File: Hash_Manifest.txt"
}

Function Compress-WinFireEvidence {
    <#
    .SYNOPSIS
        Compresses the entire output directory into a ZIP archive.
    .PARAMETER OutputPath
        The path to the output directory to compress.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [switch]$Quiet
    )
    $zipFilePath = "$($OutputPath).zip"
    Log-WinFireMessage -Type INFO -Message "Compressing evidence to: $zipFilePath" -Quiet:$Quiet

    # Check disk space before compression (simplified check)
    $drive = Split-Path -Path $OutputPath -Parent
    $driveInfo = Invoke-WinFireSafeOperation -Operation {
        Get-PSDrive -Name ($drive[0] -replace ":", "") -ErrorAction SilentlyContinue
    } -OperationName "Get Drive Info for Compression" -Quiet:$Quiet

    if ($driveInfo) {
        $totalSizeMB = (Invoke-WinFireSafeOperation -Operation {
            (Get-ChildItem -Path $OutputPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
        } -OperationName "Calculate Output Directory Size" -Quiet:$Quiet)
        if ($totalSizeMB -eq $null) { $totalSizeMB = 0 }

        $requiredSpaceEstimateMB = $totalSizeMB * 1.0 # Assume no compression or slight expansion for safety
        $freeSpaceMB = $driveInfo.Free * 1MB

        if ($freeSpaceMB -lt $requiredSpaceEstimateMB) {
            Log-WinFireMessage -Type WARN -Message "Low disk space detected on '$($driveInfo.Name)' drive. Free: $($freeSpaceMB / 1GB) GB, Estimated Required: $($requiredSpaceEstimateMB / 1GB) GB. Compression might fail." -Quiet:$Quiet
            Get-WinFireSummaryEntry -Category "Evidence Packaging" -Description "Low disk space detected, compression might be impacted." -Status "Warning" -Details "Free: $([int]($freeSpaceMB / 1GB))GB, Est. Required: $([int]($requiredSpaceEstimateMB / 1GB))GB."
        }
    }

    Invoke-WinFireSafeOperation -Operation {
        # Check for presence of Compress-Archive (PS 5.0+)
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive -Path $OutputPath -DestinationPath $zipFilePath -Force -ErrorAction Stop
            Log-WinFireMessage -Type SUCCESS -Message "Evidence package created: $zipFilePath" -Quiet:$Quiet
            Get-WinFireSummaryEntry -Category "Evidence Packaging" -Description "All collected artifacts compressed into a ZIP archive." -Status "Success" -Details "Archive: $(Split-Path $zipFilePath -Leaf)"
        } else {
            Log-WinFireMessage -Type WARN -Message "Compress-Archive cmdlet not found (requires PowerShell 5.0+). Skipping evidence packaging." -Quiet:$Quiet
            Get-WinFireSummaryEntry -Category "Evidence Packaging" -Description "Skipped evidence packaging." -Status "Warning" -Details "Compress-Archive cmdlet not available (requires PS 5.0+)."
        }
    } -OperationName "Compress Evidence Package" -Quiet:$Quiet
}

#endregion

#region Main Script Execution

# Display help if -Help is specified
if ($Help) {
    Get-Help -Full $PSScriptRoot\$($MyInvocation.MyCommand.Name)
    exit 0
}

# Set global hash algorithm
$script:GlobalHashAlgorithm = $HashAlgorithm

# Show banner
Show-WinFireBanner

# Check for Administrator privileges
Test-WinFireAdminPrivileges -ErrorAction Stop

# Initialize output directory and logging
New-WinFireOutputDirectory -BasePath $OutputPath -Quiet:$Quiet

# Initialize Chain of Custody early
Initialize-WinFireChainOfCustody -CaseNumber $CaseNumber -Investigator $Investigator -Purpose $Purpose

Log-WinFireMessage -Type INFO -Message "WinFire scan started at $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Quiet:$Quiet
Log-WinFireMessage -Type INFO -Message "Running on: $($env:COMPUTERNAME) by $($env:USERNAME)" -Quiet:$Quiet

# Fix for ternary operator in PS 5.1
$scanModeMessage = ""
if ($Quick.IsPresent) {
    $scanModeMessage = "Quick"
} elseif ($Full.IsPresent) {
    $scanModeMessage = "Full"
} else {
    $scanModeMessage = "Default (Full)"
    $Full = $true # Ensure Full is implied if neither Quick nor Full is specified
}
Log-WinFireMessage -Type INFO -Message "Scan Mode: $($scanModeMessage)" -Quiet:$Quiet
Log-WinFireMessage -Type INFO -Message "Hashing Algorithm: $HashAlgorithm" -Quiet:$Quiet


# Adjust TotalTasks based on exclusions
if ($ExcludeNetwork) { $script:TotalTasks-- }
if ($ExcludeBrowser) { $script:TotalTasks-- }

# Main scan functions
try {
    Get-WinFireSystemInfo -Quick:$Quick -Quiet:$Quiet
    Get-WinFireUserAccounts -Quick:$Quick -Quiet:$Quiet
    Get-WinFireProcessServiceAnalysis -HashAlgorithm $HashAlgorithm -Quick:$Quick -Quiet:$Quiet

    if (-not $ExcludeNetwork) {
        Get-WinFireNetworkAnalysis -Quiet:$Quiet
    } else {
        Get-WinFireSummaryEntry -Category "Network" -Description "Network analysis skipped as requested." -Status "Skipped" -Details "Excluded by -ExcludeNetwork parameter."
        $script:ProgressCounter++ # Increment counter for skipped task
    }

    Get-WinFireFileSystemAnalysis -HashAlgorithm $HashAlgorithm -Quick:$Quick -Quiet:$Quiet
    Get-WinFireRegistryAnalysis -Quick:$Quick -Quiet:$Quiet
    Get-WinFireEventLogAnalysis -Quick:$Quick -Quiet:$Quiet

    # Persistence mechanisms are broadly covered by Process/Service and Registry functions
    Get-WinFireSummaryEntry -Category "Persistence Mechanisms" -Description "Persistence mechanisms covered by Process/Service and Registry scans." -Status "Info" -Details "Check 'Running_Processes.csv', 'Services.csv', 'Scheduled_Tasks.csv', 'WMI_Event_Subscriptions.csv', 'Registry_Autoruns_Persistence.csv' for details."
    $script:ProgressCounter++

    if (-not $ExcludeBrowser) {
        Get-WinFireBrowserForensics -HashAlgorithm $HashAlgorithm -Quiet:$Quiet
    } else {
        Get-WinFireSummaryEntry -Category "Browser Forensics" -Description "Browser forensics skipped as requested." -Status "Skipped" -Details "Excluded by -ExcludeBrowser parameter."
        $script:ProgressCounter++ # Increment counter for skipped task
    }

    # Memory Analysis - only indicators in pure PS
    Get-WinFireMemoryAnalysisIndicators -Quiet:$Quiet

    Get-WinFireSecurityToolsDetection -Quiet:$Quiet

    # New: PowerShell Activity Logging Check
    Get-WinFirePowerShellActivity -Quiet:$Quiet

    # === NEW v2.0 FEATURES ===
    # Defender Exclusions Analysis
    Get-WinFireDefenderExclusions -Quiet:$Quiet

    # PowerShell Command History Collection
    Get-WinFirePowerShellHistory -Quiet:$Quiet

    # RDP Session and Connection Analysis
    Get-WinFireRDPAnalysis -Quiet:$Quiet

    # LOLBAS (Living-Off-The-Land) Detection
    Get-WinFireLOLBASDetection -Quiet:$Quiet

    # Credential Harvesting Indicators
    Get-WinFireCredentialIndicators -Quiet:$Quiet

    # Advanced Process Analysis (parent-child relationships, suspicious locations)
    Get-WinFireAdvancedProcessAnalysis -Quiet:$Quiet

    # Jump List Analysis for user activity
    Get-WinFireJumpListAnalysis -Quiet:$Quiet

    # LNK File Analysis for shortcut-based attacks
    Get-WinFireLNKAnalysis -Quiet:$Quiet

    # Calculate Overall Threat Score (should be called after all other scans)
    Get-WinFireThreatScore -Quiet:$Quiet

    # Final report generation and packaging
    New-WinFireHashManifest -CollectedFiles $script:CollectedFiles -OutputPath $script:OutputPath
    New-WinFireHtmlReport -SummaryData $script:SummaryReport -OutputPath $script:OutputPath -ChainOfCustody $script:ChainOfCustody
    Compress-WinFireEvidence -OutputPath $script:OutputPath -Quiet:$Quiet

}
catch {
    Log-WinFireMessage -Type ERROR -Message "A critical error occurred during the WinFire scan: $_" -Quiet:$Quiet
    Get-WinFireSummaryEntry -Category "Overall Scan" -Description "Script terminated due to critical error." -Status "Failed" -Details "$_"
}
finally {
    $script:EndTime = Get-Date
    $duration = ($script:EndTime - $script:StartTime).ToString("hh\:mm\:ss")
    Log-WinFireMessage -Type INFO -Message "WinFire scan finished at $($script:EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Quiet:$Quiet
    Log-WinFireMessage -Type INFO -Message "Total scan duration: $duration" -Quiet:$Quiet
    Log-WinFireMessage -Type SUCCESS -Message "WinFire scan completed! Check '$($script:OutputPath)' for results." -Quiet:$Quiet
    Write-Host "`n"
    Write-Host "=====================================================================" -ForegroundColor Green
    Write-Host " WinFire Scan Completed! Results saved to: $($script:OutputPath)" -ForegroundColor Green
    Write-Host " Total Duration: $duration" -ForegroundColor Green
    Write-Host " Review the 'WinFire_Executive_Summary.html' for an overview." -ForegroundColor Green
    Write-Host "=====================================================================" -ForegroundColor Green
}

#endregion