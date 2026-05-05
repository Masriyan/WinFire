# Contributing to WinFire 🔥

Thank you for your interest in contributing to WinFire! This guide will help you get started.

[![GitHub Issues](https://img.shields.io/github/issues/Masriyan/WinFire)](https://github.com/Masriyan/WinFire/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/Masriyan/WinFire)](https://github.com/Masriyan/WinFire/pulls)

## 📋 Table of Contents

- [Ways to Contribute](#-ways-to-contribute)
- [Development Setup](#-development-setup)
- [Code Guidelines](#-code-guidelines)
- [Function Template](#-function-template)
- [Testing](#-testing)
- [Pull Request Process](#-pull-request-process)
- [Code of Conduct](#-code-of-conduct)

## 🤝 Ways to Contribute

### 🐛 Reporting Bugs

1. Search [existing issues](https://github.com/Masriyan/WinFire/issues) first
2. Create a new issue with:
   - **Title**: Clear, descriptive summary
   - **Environment**: Windows version, PowerShell version, WinFire version
   - **Steps to Reproduce**: Detailed reproduction steps
   - **Expected vs Actual**: What you expected vs what happened
   - **Error Messages**: Full error text or screenshots

### 💡 Feature Requests

1. Open an [issue](https://github.com/Masriyan/WinFire/issues/new) with `enhancement` label
2. Describe:
   - **Forensic Value**: Why is this artifact important?
   - **Use Case**: When would investigators need this?
   - **Data Source**: Where does the data come from?
   - **Example Output**: What would the collected data look like?

### 📖 Documentation Improvements

- Fix typos or clarify existing documentation
- Add usage examples or forensic context
- Translate documentation to other languages

## 🛠️ Development Setup

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+ (Windows PowerShell)
- Git for version control
- Administrator privileges for testing

### Setup Steps

```powershell
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/WinFire.git
cd WinFire

# 3. Add upstream remote
git remote add upstream https://github.com/Masriyan/WinFire.git

# 4. Create a feature branch
git checkout -b feature/your-feature-name

# 5. Keep your fork updated
git fetch upstream
git merge upstream/main
```

## 📐 Code Guidelines

### Naming Conventions

| Element          | Convention           | Example                      |
| ---------------- | -------------------- | ---------------------------- |
| Functions        | `Get-WinFire*`       | `Get-WinFireNetworkAnalysis` |
| Variables        | `$camelCase`         | `$processData`               |
| Script Variables | `$script:PascalCase` | `$script:ResultsPath`        |
| Parameters       | `PascalCase`         | `[string]$OutputPath`        |

### Required Patterns

```powershell
# ✅ Use safe operations wrapper
$data = Invoke-WinFireSafeOperation -Operation {
    # Your code here
} -OperationName "Operation Name" -Quiet:$Quiet

# Use standard logging
Write-WinFireLog -Type INFO -Message "Message" -Quiet:$Quiet

# Use standard data export
Save-WinFireData -Data $data -FileName "Output_Name" -Quiet:$Quiet

# Add summary entry
Get-WinFireSummaryEntry -Category "Category" -Description "What was done" -Status "Success" -Details "Extra info"
```

### Code Quality

- Handle null/empty data gracefully
- Use `-ErrorAction SilentlyContinue` where appropriate
- Document function purpose with `<# .SYNOPSIS #>`
- Add `[CmdletBinding()]` to all functions (required for StrictMode compatibility)
- Keep lines under 120 characters
- Use `$script:Version` constant instead of hardcoding version strings
- Use ASCII-only characters in string literals (no Unicode box-drawing)
- Place `$null` on the left side of equality comparisons
- Avoid using PowerShell automatic variable names (`$profile`, `$event`, etc.)
- No hardcoded paths (use environment variables)
- No `Write-Host` without `-Quiet` handling
- No direct `.Privileges` or other non-existent .NET properties (verify API exists)

## 📝 Function Template

Use this template when adding new forensic collection functions:

```powershell
Function Get-WinFireNewFeature {
    <#
    .SYNOPSIS
        Brief description of what this function collects.
    .DESCRIPTION
        Detailed forensic value and context.
    .PARAMETER Quiet
        Suppress console output when true.
    #>
    [CmdletBinding()]
    param([switch]$Quiet)

    # Progress tracking
    $script:ProgressCounter++
    Set-WinFireProgress -Activity "Feature Name" `
        -Status "Collecting feature data..." `
        -CurrentValue $script:ProgressCounter `
        -MaxValue $script:TotalTasks

    # Initialize results
    $results = @()

    # Safe data collection
    $collectedData = Invoke-WinFireSafeOperation -Operation {
        # Your collection logic here
        Get-CimInstance Win32_SomeClass | Select-Object Property1, Property2
    } -OperationName "Collect Feature Data" -Quiet:$Quiet

    # Process and format data
    if ($collectedData) {
        foreach ($item in $collectedData) {
            $results += [PSCustomObject]@{
                Property1 = $item.Property1
                Property2 = $item.Property2
                CollectedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
    }

    # Export data
    Save-WinFireData -Data $results -FileName "Feature_Name" -Quiet:$Quiet

    # Add to summary report
    Get-WinFireSummaryEntry `
        -Category "Feature Category" `
        -Description "Collected feature data for analysis." `
        -Status "Success" `
        -Details "Found $($results.Count) items."
}
```

## 🧪 Testing

### Manual Testing Checklist

Before submitting a PR, test on:

- [ ] Windows 10 (latest)
- [ ] Windows 11 (latest)
- [ ] Windows Server 2019/2022 (if possible)

### Test Scenarios

```powershell
# 1. Quick scan mode
.\WinFire.ps1 -Quick -OutputPath "C:\Test\Quick"

# 2. Full scan mode
.\WinFire.ps1 -Full -OutputPath "C:\Test\Full"

# 3. With exclusions
.\WinFire.ps1 -Quick -ExcludeNetwork -ExcludeBrowser -OutputPath "C:\Test\Exclude"

# 4. Quiet mode
.\WinFire.ps1 -Quick -Quiet -OutputPath "C:\Test\Quiet"

# 5. Verify outputs
Get-ChildItem "C:\Test\Quick\Raw_Data" | Measure-Object
Get-Content "C:\Test\Quick\WinFire_ExecutionLog.txt" -Tail 50
```

### Verify Your Changes

1. ✅ New CSV/JSON files are created
2. ✅ No errors in execution log
3. ✅ HTML report includes new category
4. ✅ Script completes without exceptions

## 📤 Pull Request Process

### Before Submitting

1. Update `CHANGELOG.md` with your changes
2. Increment `$script:TotalTasks` if adding new function
3. Update `README.md` if adding user-visible features
4. Test on at least one Windows version

### PR Description Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing Done

- [ ] Tested on Windows 10/11
- [ ] Quick scan works
- [ ] Full scan works
- [ ] No new errors in log

## Checklist

- [ ] Code follows project style
- [ ] CHANGELOG.md updated
- [ ] Documentation updated
```

### Review Process

1. Maintainers will review within 1-2 weeks
2. Address any requested changes
3. Once approved, PR will be merged

## 📜 Code of Conduct

### Our Standards

- ✅ Be respectful and inclusive
- ✅ Focus on constructive feedback
- ✅ Help others learn
- ✅ Accept responsibility for mistakes
- ❌ No harassment or discrimination
- ❌ No personal attacks

### Enforcement

Violations may result in:

1. Warning
2. Temporary ban
3. Permanent ban

Report issues to: **sudo3rs@protonmail.com**

## 📞 Contact

- **GitHub Issues**: [https://github.com/Masriyan/WinFire/issues](https://github.com/Masriyan/WinFire/issues)
- **Discussions**: [https://github.com/Masriyan/WinFire/discussions](https://github.com/Masriyan/WinFire/discussions)
- **Email**: sudo3rs@protonmail.com

---

**Thank you for contributing to WinFire! 🔥**
