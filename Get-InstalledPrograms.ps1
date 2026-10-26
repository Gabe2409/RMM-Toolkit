#Requires -Version 5.1
<#
.SYNOPSIS
    Everyday installed-program inventory from the registry (not Win32_Product,
    which is slow and triggers MSI self-repair).

.EXAMPLE
    .\Get-InstalledPrograms.ps1                    # alphabetical
    .\Get-InstalledPrograms.ps1 -ByInstallDate     # newest first, for incident work
    .\Get-InstalledPrograms.ps1 -IncludeHidden     # also show SystemComponent=1 entries
    .\Get-InstalledPrograms.ps1 -ByInstallDate | Out-GridView
#>
[CmdletBinding()]
param([switch]$ByInstallDate, [switch]$IncludeHidden)

Import-Module (Join-Path $PSScriptRoot 'lib\RMMToolkit.Common.psm1') -Force -DisableNameChecking

$rows = Get-UninstallEntries | Where-Object { $_.DisplayName -and ($IncludeHidden -or -not $_.SystemComponent) }
if ($ByInstallDate) {
    $rows | Sort-Object @{e={ if ($_.InstallDate) { $_.InstallDate } else { [datetime]::MinValue } }} -Descending |
        Select-Object DisplayName, Publisher, @{n='InstallDate';e={ if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } }}, InstallLocation, @{n='Hidden';e={ $_.SystemComponent }}
} else {
    $rows | Sort-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, @{n='InstallDate';e={ if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } }}, @{n='Hidden';e={ $_.SystemComponent }}
}
