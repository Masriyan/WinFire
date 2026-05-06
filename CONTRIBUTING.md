# Contributing to WinFire

Thank you for helping improve WinFire. This project is a Windows DFIR tool, so reliability, forensic correctness, and clear documentation matter more than broad refactors.

## Ways to Contribute

### Bug Reports

Open an issue with:

- WinFire version.
- Windows version.
- PowerShell version.
- Command line used.
- Expected behavior.
- Actual behavior.
- Relevant lines from `WinFire_ExecutionLog.txt`.
- Whether the session was elevated.

Do not paste sensitive forensic data into public issues.

### Feature Requests

Include:

- Forensic value.
- Windows data source.
- Required privileges.
- Expected CSV/JSON schema.
- Whether the module should run in `-Quick`, `-Full`, or both.
- Expected HTML report and threat scoring impact.

### Documentation

Documentation updates should stay current with:

- Script version and build date.
- Parameters.
- Raw output file names.
- Known warnings and live-system limitations.
- Testing instructions.

## Development Setup

Requirements:

- Windows 10/11 or Windows Server 2016+.
- Windows PowerShell 5.1+.
- Administrator privileges for real scan testing.
- Git if available.

Example setup:

```powershell
git clone https://github.com/Masriyan/WinFire.git
cd WinFire
```

If `git` is not available, work directly from the source directory and keep manual notes of changed files.

## Coding Standards

### PowerShell Compatibility

- Maintain Windows PowerShell 5.1 compatibility.
- Do not require PowerShell 7-only features.
- Use `Get-CimInstance`, not `Get-WmiObject`.
- Use ASCII string literals unless there is a specific forensic reason.
- Keep output stable for CSV/JSON consumers.

### Naming

| Element | Convention | Example |
| --- | --- | --- |
| Collection functions | `Get-WinFire*` | `Get-WinFireNetworkAnalysis` |
| Summary function | `Add-WinFireSummaryEntry` | `Add-WinFireSummaryEntry -Category "Network"` |
| Logging function | `Write-WinFireLog` | `Write-WinFireLog -Type INFO` |
| Script state | `$script:PascalCase` | `$script:ResultsPath` |
| Local variables | `$camelCase` | `$processList` |

### Required Patterns

All forensic operations should use `Invoke-WinFireSafeOperation`:

```powershell
$data = Invoke-WinFireSafeOperation -Operation {
    Get-CimInstance Win32_Service |
        Select-Object Name, State, StartMode, PathName
} -OperationName "Collect Service Details" -Quiet:$Quiet
```

Save structured output through `Save-WinFireData`:

```powershell
Save-WinFireData -Data $data -FileName "Services_Detail" -Quiet:$Quiet
```

Add report summary entries with the approved verb:

```powershell
Add-WinFireSummaryEntry `
    -Category "Services" `
    -Description "Collected detailed service configuration." `
    -Status "Success" `
    -Details "Collected $(@($data).Count) services."
```

### Function Template

```powershell
Function Get-WinFireNewArtifact {
    <#
    .SYNOPSIS
        Collects a concise description of the artifact.
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick,
        [switch]$Quiet
    )

    $script:ProgressCounter++
    Set-WinFireProgress `
        -Activity "New Artifact" `
        -Status "Collecting new artifact..." `
        -CurrentValue $script:ProgressCounter `
        -MaxValue $script:TotalTasks

    $results = Invoke-WinFireSafeOperation -Operation {
        # Collection logic here.
        @()
    } -OperationName "Collect New Artifact" -Quiet:$Quiet

    Save-WinFireData -Data $results -FileName "New_Artifact" -Quiet:$Quiet

    Add-WinFireSummaryEntry `
        -Category "New Artifact" `
        -Description "Collected new artifact data." `
        -Status "Success" `
        -Details "Collected $(@($results).Count) rows."
}
```

### Error Handling

- Prefer typed catches for expected failures:
  - `[System.UnauthorizedAccessException]`
  - `[System.IO.IOException]`
- For locked live-system artifacts, record a row with status/error when possible instead of failing the whole scan.
- Avoid direct `exit` inside helper functions. Return status and let the main block decide the exit code.
- Avoid destructive operations.

### Progress and Task Counts

If you add or remove a top-level progress unit:

1. Increment/decrement `Get-WinFirePlannedTaskCount`.
2. Ensure the new function increments `$script:ProgressCounter`.
3. Ensure skipped sections still advance progress or are reflected in the planned count.

### Report and Threat Score

If a new module is user-visible:

- Add raw output documentation to `README.md`.
- Add an HTML report section when the result changes investigation decisions.
- Add threat scoring only for high-signal indicators.
- Avoid double counting a summary warning and raw-data indicator for the same finding.
- Classify noisy artifacts before scoring them.

## Testing

### Static Validation

Run:

```powershell
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\WinFire.ps1),
    [ref]$tokens,
    [ref]$parseErrors
) | Out-Null
$parseErrors
```

Expected result: no parse errors.

Check for deprecated patterns:

```powershell
Select-String -Path .\WinFire.ps1 -Pattern 'Get-WmiObject','Get-WinFireSummaryEntry'
```

Expected result: no matches.

### Help Test

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Help
```

### Runtime Test

Run from elevated PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinFire.ps1 -Quick -OutputPath .\WinFire_TestRuns -Quiet
```

Review:

```powershell
$latest = Get-ChildItem .\WinFire_TestRuns -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

Import-Csv "$($latest.FullName)\Reports\Operation_Metrics.csv" |
    Where-Object { $_.Status -ne 'Success' }

Import-Csv "$($latest.FullName)\Raw_Data\Threat_Score.csv" |
    Format-List
```

Expected:

- Script completes.
- No unexpected failed operations.
- Raw output files are present.
- HTML report is generated.
- Locked live files are warnings or recorded rows, not critical crashes.

## Pull Request Checklist

- [ ] Code parses in Windows PowerShell 5.1.
- [ ] No `Get-WmiObject`.
- [ ] No `Get-WinFireSummaryEntry`.
- [ ] New functions have `[CmdletBinding()]`.
- [ ] New collection logic uses `Invoke-WinFireSafeOperation`.
- [ ] New data is saved through `Save-WinFireData`.
- [ ] Progress count is updated.
- [ ] README is updated for user-visible changes.
- [ ] CHANGELOG is updated.
- [ ] SECURITY is updated if collection sensitivity changes.
- [ ] Runtime tested with at least `-Quick`.

## Code of Conduct

- Be respectful and direct.
- Keep review comments technical and actionable.
- Do not post private forensic data publicly.
- Do not submit code that enables unauthorized access, persistence, evasion, or credential theft outside legitimate defensive collection.

## Contact

- Issues: [https://github.com/Masriyan/WinFire/issues](https://github.com/Masriyan/WinFire/issues)
- Discussions: [https://github.com/Masriyan/WinFire/discussions](https://github.com/Masriyan/WinFire/discussions)
- Email: sudo3rs@protonmail.com
