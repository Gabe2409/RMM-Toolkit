#Requires -Version 5.1
<#
.SYNOPSIS
    Narrowly scoped removal of ScreenConnect / ConnectWise Control client
    instances, with evidence preservation and verification.

.DESCRIPTION
    Touches ScreenConnect ONLY. It does not interact with antivirus, other
    RMM products, user accounts, firewall or network settings.

    Order of operations:
      0. Discover instances and decide targets (refuses ambiguous cases)
      1. Preserve evidence: IOCs, registry exports, file hashes, configs,
         ScreenConnect event-log entries, optional zip of install folders
      2. Contain: disable + stop the client service(s), then end remaining
         ScreenConnect processes (service first so it can't respawn them)
      3. Run the registered Windows Installer uninstall (msiexec /x)
      4. Delete orphaned ScreenConnect services left behind
      5. Remove ScreenConnect scheduled tasks, Run-key values, Startup shortcuts
      6. Inspect LSA package registration - report only, unless
         -RemoveLsaEntry is given (backed up, msv1_0 sanity-checked)
      7. Remove remaining ScreenConnect folders
      8. Rescan and verify

    Every destructive step honours -WhatIf and asks for confirmation unless
    -Force is supplied.

.PARAMETER ClientId
    One or more client IDs (the hex in "ScreenConnect Client (xxxx)") to remove.
    Required when the machine has more than one instance, unless -AllInstances.

.PARAMETER AllInstances
    Target every ScreenConnect instance found, except ones whose callback
    host is listed in config\ioc-watchlist.json trustedTenantHosts
    (add -IncludeTrusted to remove those too).

.PARAMETER RemoveLsaEntry
    If, after uninstall, a ScreenConnect entry is still listed in the LSA
    package values, remove ONLY that entry (after a reg export backup).

.PARAMETER VerifyOnly
    Make no changes; rescan and report whether any ScreenConnect remains.
    Run this after the offline reboot.

.PARAMETER SkipEvidenceArchive
    Don't zip the install folders (hashes and configs are still kept).

.EXAMPLE
    .\ScreenConnect-Cleanup.ps1 -WhatIf               # dry run
    .\ScreenConnect-Cleanup.ps1                       # single instance, prompts per step
    .\ScreenConnect-Cleanup.ps1 -ClientId 1a2b3c4d5e6f7a8b -Force
    .\ScreenConnect-Cleanup.ps1 -VerifyOnly           # after offline reboot
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$ClientId,
    [switch]$AllInstances,
    [switch]$IncludeTrusted,
    [switch]$RemoveLsaEntry,
    [switch]$VerifyOnly,
    [switch]$SkipEvidenceArchive,
    [switch]$Force,
    [string]$OutputRoot = 'C:\Users\Public\RMM-Triage'
)

$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'lib\RMMToolkit.Common.psm1') -Force -DisableNameChecking

# -WhatIf = dry run. We take it over ourselves so evidence/report files are
# still written during a dry run; only the destructive steps are skipped.
$DryRun = [bool]$WhatIfPreference
$WhatIfPreference = $false
$script:ApproveAll = [bool]$Force

function Approve-Step([string]$Target, [string]$Operation) {
    if ($DryRun) { Write-TriageLog "WHATIF: would $Operation -> $Target" -Level ACTION; return $false }
    if ($script:ApproveAll) { return $true }
    $a = Read-Host "$Operation -> $Target  [y]es / [n]o / [a]ll"
    if ($a -match '^a') { $script:ApproveAll = $true; return $true }
    return ($a -match '^y')
}

$label = if ($VerifyOnly) { 'sc-verify' } else { 'sc-cleanup' }
$out   = Initialize-TriageOutput -Root $OutputRoot -Label $label
$evid  = Join-Path $out 'evidence'; New-Item -ItemType Directory -Path $evid -Force | Out-Null
try { $cfg = Import-ToolkitConfig -ConfigDir (Join-Path $PSScriptRoot 'config') }
catch { Write-TriageLog "Config error: $($_.Exception.Message) Fix the config files. Nothing was changed." -Level ERROR; exit 13 }
$actions = New-Object System.Collections.Generic.List[object]

function Add-Action([string]$Step, [string]$Target, [string]$Result) {
    $actions.Add([pscustomobject]@{ Time = Get-Date; Step = $Step; Target = $Target; Result = $Result })
    $lvl = if ($Result -match '^(OK|Removed|Stopped|Disabled|Uninstalled)') { 'ACTION' } elseif ($Result -match 'FAIL|ERROR') { 'ERROR' } else { 'INFO' }
    Write-TriageLog "$Step | $Target | $Result" -Level $lvl
}

function Get-ScreenConnectState {
    # Everything ScreenConnect-related on the box, as one object (read-only)
    $svc   = @(Get-ServiceInventory)
    $inst  = @(Get-ScreenConnectInstances -Services $svc)
    $procs = @(Get-ProcessInventory | Where-Object { $_.Name -match '^ScreenConnect\.' -or $_.ExecutablePath -match 'ScreenConnect' })
    $unin  = @(Get-UninstallEntries | Where-Object { $_.DisplayName -match 'ScreenConnect' -or $_.Publisher -match 'ScreenConnect Software' })
    $msi   = @(Get-MsiProductRegistrations | Where-Object { $_.ProductName -match 'ScreenConnect' })
    $tasks = @(Get-ScheduledTaskInventory | Where-Object { $_.TaskName -match 'ScreenConnect' -or $_.Actions -match 'ScreenConnect' })
    $run   = @(Get-RunKeyEntries | Where-Object { $_.Name -match 'ScreenConnect' -or $_.Command -match 'ScreenConnect' })
    $start = @(Get-StartupFolderEntries | Where-Object { $_.Name -match 'ScreenConnect' -or $_.Target -match 'ScreenConnect' })
    $dirs  = @(Get-ScreenConnectFolders)
    $sysDlls = @(foreach ($d in "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64") { Get-ChildItem -LiteralPath $d -Filter 'ScreenConnect*' -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName })
    $lsa   = Get-LsaAuthenticationPackages
    $lsaSc = @(@($lsa.AuthenticationPackages) + @($lsa.SecurityPackages) + @($lsa.NotificationPackages) | Where-Object { $_ -match 'ScreenConnect' })
    $orph  = @($svc | Where-Object { $_.Name -match '^ScreenConnect' -and -not ($inst | Where-Object ServiceName -eq $_.Name) })
    [pscustomobject][ordered]@{
        Instances = $inst; OtherServices = $orph; Processes = $procs; Uninstall = $unin; Msi = $msi
        Tasks = $tasks; RunKeys = $run; Startup = $start; Folders = $dirs; SystemDlls = $sysDlls; Lsa = $lsa; LsaScreenConnect = $lsaSc
    }
}

$isAdmin = Test-IsAdmin
Write-TriageLog "ScreenConnect-Cleanup | Host $env:COMPUTERNAME | User $env:USERDOMAIN\$env:USERNAME | Admin=$isAdmin | VerifyOnly=$VerifyOnly | DryRun=$DryRun"
if (-not $isAdmin -and -not $VerifyOnly) {
    Write-TriageLog 'Must be run as Administrator. Nothing was changed.' -Level ERROR
    exit 10
}

# ---------------------------------------------------------------------------
# 0. Discover + decide targets
# ---------------------------------------------------------------------------
$before = Get-ScreenConnectState
$before | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $evid 'state-before.json') -Encoding UTF8

foreach ($i in $before.Instances) {
    Write-TriageLog ("Instance: id={0} host={1} port={2} session={3} e={4} svc='{5}' [{6}]" -f $i.ClientId, $i.CallbackHost, $i.CallbackPort, $i.SessionId, $i.SessionType, $i.ServiceName, $i.State) -Level HIGH
}



$trustedHosts = @($cfg.Watchlist.trustedTenantHosts)

if ($VerifyOnly) {
    # Trusted (own MSP) instances are expected to stay; -IncludeTrusted verifies they are gone too
    $kept = if ($IncludeTrusted) { @() } else { @($before.Instances | Where-Object { Test-HostListed $_.CallbackHost $trustedHosts -Trusted }) }
    $rem = Write-VerificationReport $before 'Verification' $kept
    $text = @("SCREENCONNECT VERIFICATION - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
              "Result: $(if ($rem.Count) { 'FAIL - items remain' } else { 'PASS - nothing remains' })", '') + @($rem | ForEach-Object { "  $_" })
    $text | Set-Content (Join-Path $out 'verification.txt') -Encoding UTF8
    $next = if ($rem.Count) { 'Items remain: run Cleanup again (offline), reboot, then Verify.', 'Cleanup' } else { 'Clean. Run Triage once more for a full rescan, then reconnect the network.', 'Triage' }
    Write-ToolkitResult -Folder $out -Tool Verify -ExitCode ([int][bool]$rem.Count) -Verdict $(if ($rem.Count) { 'Red' } else { 'Green' }) `
        -Instances $before.Instances -TrustedHosts $trustedHosts -Findings @($rem | ForEach-Object { [pscustomobject]@{ Severity = 'High'; Category = 'Remaining'; Title = $_ } }) `
        -NextStep $next[0] -NextAction $next[1] -SummaryPath (Join-Path $out 'verification.txt')
    if ($rem.Count) { exit 1 } else { exit 0 }
}

$targets = @()
if ($ClientId) {
    # Split on commas too: powershell.exe -File passes "-ClientId a,b" as one string
    $ClientId = @($ClientId | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.ToLower().Trim('(',')',' ') } | Where-Object { $_ })
    $targets  = @($before.Instances | Where-Object { $ClientId -contains $_.ClientId })
    $missing  = @($ClientId | Where-Object { $_ -notin @($before.Instances.ClientId) })
    foreach ($m in $missing) { Write-TriageLog "Client ID $m has no running service; will still clean its leftovers (folders, entries)." -Level WARN }
} elseif ($AllInstances) {
    $targets = @($before.Instances | Where-Object { $IncludeTrusted -or -not (Test-HostListed $_.CallbackHost $trustedHosts -Trusted) })
    $ClientId = @($targets.ClientId | Where-Object { $_ })
} else {
    if ($before.Instances.Count -gt 1) {
        Write-TriageLog 'More than one ScreenConnect instance found. Re-run with -ClientId <id> (preferred) or -AllInstances. Nothing was changed.' -Level ERROR
        exit 11
    }
    $targets  = @($before.Instances)
    $ClientId = @($targets.ClientId | Where-Object { $_ })
}

# Never touch a trusted (your own MSP) instance unless explicitly asked
if (-not $IncludeTrusted) {
    $trustedTargets = @($targets | Where-Object { Test-HostListed $_.CallbackHost $trustedHosts -Trusted })
    foreach ($t in $trustedTargets) { Write-TriageLog "Skipping $($t.ClientId): callback host $($t.CallbackHost) is on the trusted list (use -IncludeTrusted to override)." -Level WARN }
    $targets  = @($targets | Where-Object { $trustedTargets -notcontains $_ })
    if (-not $PSBoundParameters.ContainsKey('ClientId') -or $trustedTargets) { $ClientId = @($targets.ClientId | Where-Object { $_ }) }
}
$survivors = @($before.Instances | Where-Object { $targets -notcontains $_ })
if ($survivors -and -not $ClientId) {
    Write-TriageLog 'No instance is in scope and other ScreenConnect instances exist; refusing to clean unscoped remnants. Nothing was changed.' -Level ERROR
    exit 12
}

$scope = if ($ClientId) { $ClientId -join ', ' } else { 'ALL ScreenConnect remnants (no service found)' }
Write-TriageLog "Target scope: $scope" -Level ACTION
if (-not $targets -and -not $before.Folders -and -not $before.Uninstall -and -not $before.Msi -and -not $before.OtherServices -and
    -not $before.Tasks -and -not $before.RunKeys -and -not $before.Startup -and -not $before.SystemDlls -and -not $before.LsaScreenConnect) {
    Write-TriageLog 'Nothing to remove.' -Level OK
    Write-ToolkitResult -Folder $out -Tool Cleanup -ExitCode 0 -Verdict Green -DryRun $DryRun -Instances $before.Instances -TrustedHosts $trustedHosts `
        -NextStep 'No ScreenConnect left to remove. Run Verify after a reboot.' -NextAction Verify
    exit 0
}

# Items in scope (helpers filter leftovers by client ID when IDs are known)
$inScopeFolders = @($before.Folders | Where-Object { Test-InScope $_ $ClientId })
# Shared, non-instance folders (e.g. ProgramData\ScreenConnect) only when no other instance survives
if (-not $survivors) { $inScopeFolders += @($before.Folders | Where-Object { $_ -notmatch 'ScreenConnect Client \(' }) }
$inScopeFolders = @($inScopeFolders | Select-Object -Unique)

# ---------------------------------------------------------------------------
# 1. Evidence
# ---------------------------------------------------------------------------
Write-TriageLog '--- 1. Preserving evidence ---'
$targets | Select-Object ClientId, CallbackHost, CallbackPort, SessionId, SessionType, ClientType, ServiceName, InstallFolder, ImagePath, @{n='CustomProps';e={ @($_.CustomProps) -join ' | ' }} |
    Export-Csv (Join-Path $evid 'ioc.csv') -NoTypeInformation -Encoding UTF8

$regExports = @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa')
foreach ($t in $targets) { $regExports += "HKLM\SYSTEM\CurrentControlSet\Services\$($t.ServiceName)" }
foreach ($o in $before.OtherServices) { $regExports += "HKLM\SYSTEM\CurrentControlSet\Services\$($o.Name)" }
foreach ($u in $before.Uninstall) { if (Test-InScope $u.DisplayName $ClientId) { $regExports += ($u.RegistryPath -replace '^HKEY_LOCAL_MACHINE','HKLM' -replace '^HKEY_CURRENT_USER','HKCU' -replace '^HKEY_USERS','HKU') } }
$n = 0
foreach ($r in ($regExports | Select-Object -Unique)) {
    $n++
    $file = Join-Path $evid ('reg-{0:00}-{1}.reg' -f $n, (($r -split '\\')[-1] -replace '[^\w\-\(\)]','_'))
    & reg.exe export "$r" "$file" /y *> $null
    Add-Action 'Evidence' "reg export $r" $(if ($LASTEXITCODE -eq 0) { 'OK' } else { "skipped (exit $LASTEXITCODE)" })
}

$hashRows = New-Object System.Collections.Generic.List[object]
foreach ($f in $inScopeFolders) {
    Get-ChildItem -LiteralPath $f -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $sigInfo = Get-SignatureSummary $_.FullName
        $hashRows.Add([pscustomobject]@{ Path = $_.FullName; Size = $_.Length; Created = $_.CreationTime; Modified = $_.LastWriteTime; SHA256 = Get-FileHashSafe $_.FullName; Signature = $sigInfo.Status; Signer = $sigInfo.Signer })
        if ($_.Extension -in '.config','.xml','.log','.txt','.json' -and $_.Length -lt 5MB) {
            $dest = Join-Path $evid ('cfg_' + (($_.FullName -replace '[:\\ ]','_')))
            Copy-Item -LiteralPath $_.FullName -Destination $dest -ErrorAction SilentlyContinue
        }
    }
}
$hashRows | Export-Csv (Join-Path $evid 'file-hashes.csv') -NoTypeInformation -Encoding UTF8
Add-Action 'Evidence' 'file hashes + config copies' "OK ($($hashRows.Count) files)"

try {
    $prov = @(Get-WinEvent -ListProvider 'ScreenConnect*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($prov) {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $prov } -MaxEvents 5000 -ErrorAction Stop |
            Select-Object TimeCreated, ProviderName, Id, @{n='Message';e={ $_.Message -replace '\s+',' ' }} |
            Export-Csv (Join-Path $evid 'screenconnect-events.csv') -NoTypeInformation -Encoding UTF8
        Add-Action 'Evidence' 'ScreenConnect event-log entries' 'OK'
    }
} catch { Add-Action 'Evidence' 'ScreenConnect event-log entries' "skipped ($($_.Exception.Message))" }

if (-not $SkipEvidenceArchive -and $inScopeFolders) {
    $zip = Join-Path $evid 'install-folders.zip'
    try {
        Compress-Archive -Path $inScopeFolders -DestinationPath $zip -CompressionLevel Optimal -Force -ErrorAction Stop
        Add-Action 'Evidence' 'install folders archived' "OK ($([math]::Round((Get-Item $zip).Length/1MB,1)) MB)"
    } catch { Add-Action 'Evidence' 'install folders archived' "skipped ($($_.Exception.Message)) - hashes still recorded" }
}

# ---------------------------------------------------------------------------
# 2. Contain: disable + stop service, then end processes
# ---------------------------------------------------------------------------
Write-TriageLog '--- 2. Stopping ScreenConnect ---'
foreach ($t in $targets) {
    if (Approve-Step $t.ServiceName 'Disable and stop service') {
        try { Set-Service -Name $t.ServiceName -StartupType Disabled -ErrorAction Stop; Add-Action 'Contain' $t.ServiceName 'Disabled' } catch { Add-Action 'Contain' $t.ServiceName "disable FAILED: $($_.Exception.Message)" }
        try { Stop-Service -Name $t.ServiceName -Force -ErrorAction Stop; Add-Action 'Contain' $t.ServiceName 'Stopped' } catch { Add-Action 'Contain' $t.ServiceName "stop FAILED: $($_.Exception.Message)" }
    }
}
Start-Sleep -Seconds 2
$targetFolders = @($targets | ForEach-Object { $_.InstallFolder } | Where-Object { $_ })
foreach ($p in (Get-ProcessInventory | Where-Object { $_.Name -match '^ScreenConnect\.' })) {
    $own = ((-not $p.ExecutablePath) -and -not $survivors) -or (@($targetFolders | Where-Object { $p.ExecutablePath -like "$_*" }).Count -gt 0) -or (-not $survivors -and (Test-InScope $p.ExecutablePath $ClientId))
    if (-not $own) { continue }
    if (Approve-Step "$($p.Name) (PID $($p.ProcessId))" 'End process') {
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Add-Action 'Contain' "$($p.Name) PID $($p.ProcessId)" 'Stopped' }
        catch { Add-Action 'Contain' "$($p.Name) PID $($p.ProcessId)" "FAILED: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# 3. Registered uninstaller (Windows Installer only - never arbitrary strings)
# ---------------------------------------------------------------------------
Write-TriageLog '--- 3. Registered uninstall ---'
$productCodes = New-Object System.Collections.Generic.List[string]
foreach ($u in $before.Uninstall) {
    if (-not (Test-InScope $u.DisplayName $ClientId)) { continue }
    $code = $null
    if ($u.UninstallString -match 'msiexec(\.exe)?.*?(\{[0-9A-Fa-f\-]{36}\})') { $code = $Matches[2] }
    elseif ($u.KeyName -match '^\{[0-9A-Fa-f\-]{36}\}$') { $code = $u.KeyName }
    if ($code) { $productCodes.Add($code.ToUpper()) }
    else { Add-Action 'Uninstall' $u.DisplayName "no MSI product code; uninstall string not executed: $($u.UninstallString)" }
}
# Fallback: Installer registry (catches entries hidden/removed from the Uninstall key)
foreach ($m in $before.Msi) { if ((Test-InScope $m.ProductName $ClientId) -and $m.ProductCode) { $productCodes.Add($m.ProductCode.ToUpper()) } }

foreach ($code in ($productCodes | Select-Object -Unique)) {
    if (Approve-Step $code 'msiexec /x (quiet)') {
        $log = Join-Path $evid ("msiexec-uninstall-{0}.log" -f ($code -replace '[{}]',''))
        $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList @('/x', $code, '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru -WindowStyle Hidden
        $meaning = switch ($p.ExitCode) { 0 {'Uninstalled'} 3010 {'Uninstalled (reboot required)'} 1605 {'not installed (already gone)'} 1618 {'FAILED: another install is running'} default {"FAILED: exit $($p.ExitCode)"} }
        Add-Action 'Uninstall' $code $meaning
    }
}

# ---------------------------------------------------------------------------
# 4. Orphaned services
# ---------------------------------------------------------------------------
Write-TriageLog '--- 4. Orphaned services ---'
$svcNow = @(Get-ServiceInventory | Where-Object { $_.Name -match '^ScreenConnect' -and (Test-InScope $_.Name $ClientId) })
foreach ($s in $svcNow) {
    if (Approve-Step $s.Name 'Delete service') {
        try { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue } catch { }
        $r = & sc.exe delete "$($s.Name)" 2>&1
        Add-Action 'Service' $s.Name $(if ($LASTEXITCODE -eq 0) { 'Removed' } else { "FAILED: $r" })
    }
}

# ---------------------------------------------------------------------------
# 5. Tasks / Run keys / Startup shortcuts
# ---------------------------------------------------------------------------
Write-TriageLog '--- 5. Startup remnants ---'
foreach ($t in $before.Tasks) {
    if (-not $survivors -or (Test-InScope "$($t.TaskName) $($t.Actions)" $ClientId)) {
        if (Approve-Step "$($t.TaskPath)$($t.TaskName)" 'Unregister scheduled task') {
            try {
                $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
                if ($xml) { $xml | Set-Content (Join-Path $evid ("task_" + ($t.TaskName -replace '[^\w\-]','_') + '.xml')) -Encoding UTF8 }
                Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                Add-Action 'Task' "$($t.TaskPath)$($t.TaskName)" 'Removed'
            } catch { Add-Action 'Task' $t.TaskName "FAILED: $($_.Exception.Message)" }
        }
    }
}
foreach ($r in $before.RunKeys) {
    if (-not $survivors -or (Test-InScope $r.Command $ClientId)) {
        if (Approve-Step "$($r.Location)\$($r.Name)" 'Remove Run value') {
            try { Remove-ItemProperty -Path $r.Location -Name $r.Name -ErrorAction Stop; Add-Action 'RunKey' "$($r.Location)\$($r.Name)" "Removed (was: $($r.Command))" }
            catch { Add-Action 'RunKey' $r.Name "FAILED: $($_.Exception.Message)" }
        }
    }
}
foreach ($s in $before.Startup) {
    if (-not $survivors -or (Test-InScope $s.Target $ClientId)) {
        $path = Join-Path $s.Location $s.Name
        if (Approve-Step $path 'Remove Startup item') {
            try { Copy-Item -LiteralPath $path -Destination $evid -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $path -Force -ErrorAction Stop; Add-Action 'Startup' $path 'Removed' }
            catch { Add-Action 'Startup' $path "FAILED: $($_.Exception.Message)" }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. LSA packages - inspect, change only on explicit request
# ---------------------------------------------------------------------------
Write-TriageLog '--- 6. LSA package registration ---'
$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaNow = Get-LsaAuthenticationPackages
Write-TriageLog ("Authentication Packages: {0}" -f (@($lsaNow.AuthenticationPackages) -join ', '))
Write-TriageLog ("Security Packages      : {0}" -f (@($lsaNow.SecurityPackages) -join ', '))
Write-TriageLog ("Notification Packages  : {0}" -f (@($lsaNow.NotificationPackages) -join ', '))
$lsaLeft = $false
foreach ($valueName in 'Authentication Packages','Security Packages','Notification Packages') {
    $current = @(switch ($valueName) { 'Authentication Packages' { $lsaNow.AuthenticationPackages } 'Security Packages' { $lsaNow.SecurityPackages } default { $lsaNow.NotificationPackages } })
    $scEntries = @($current | Where-Object { $_ -match '^ScreenConnect' })
    if (-not $scEntries) { continue }
    $lsaLeft = $true
    if (-not $RemoveLsaEntry) {
        Add-Action 'LSA' $valueName "ScreenConnect entry still present ($($scEntries -join ', ')). NOT changed. Re-run with -RemoveLsaEntry after review."
        continue
    }
    $newList = @($current | Where-Object { $_ -notmatch '^ScreenConnect' })
    if ($valueName -eq 'Authentication Packages' -and ($newList -notcontains 'msv1_0')) {
        Add-Action 'LSA' $valueName 'FAILED safety check: msv1_0 would not remain. NOT changed.'
        continue
    }
    if (-not (Test-Path -LiteralPath (Join-Path $evid 'reg-01-Lsa.reg'))) {
        Add-Action 'LSA' $valueName 'FAILED safety check: no LSA backup (evidence\reg-01-Lsa.reg). NOT changed.'
        continue
    }
    if (Approve-Step "$lsaKey\$valueName" "Remove entries: $($scEntries -join ', ')") {
        try {
            Set-ItemProperty -Path $lsaKey -Name $valueName -Value ([string[]]$newList) -Type MultiString -ErrorAction Stop
            Add-Action 'LSA' $valueName "Removed $($scEntries -join ', ') (backup in evidence\reg-01-Lsa.reg). New: $($newList -join ', ')"
            $lsaLeft = $false
        } catch { Add-Action 'LSA' $valueName "FAILED: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# 7. Folders (+ System32 copies of the auth package once unregistered)
# ---------------------------------------------------------------------------
Write-TriageLog '--- 7. Folders ---'
$allowedRoots = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemRoot\System32\config\systemprofile", "$env:SystemRoot\SysWOW64\config\systemprofile", 'C:\Users') | Where-Object { $_ }
foreach ($f in $inScopeFolders) {
    if (-not (Test-Path -LiteralPath $f)) { Add-Action 'Folder' $f 'already gone'; continue }
    $leaf = Split-Path -Leaf $f
    $rooted = @($allowedRoots | Where-Object { $f -like "$_\*" }).Count -gt 0
    if ($leaf -notmatch '^ScreenConnect' -or -not $rooted) { Add-Action 'Folder' $f 'skipped (outside safety rules)'; continue }
    if (Approve-Step $f 'Delete folder') {
        try { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop; Add-Action 'Folder' $f 'Removed' }
        catch { Add-Action 'Folder' $f "FAILED (likely locked - re-run after reboot): $($_.Exception.Message)" }
    }
}
foreach ($dll in $before.SystemDlls) {
    if ($lsaLeft) { Add-Action 'SystemDll' $dll 'kept - still referenced by LSA; removing it while registered is not done by this tool'; continue }
    if ($survivors) { Add-Action 'SystemDll' $dll 'kept - another ScreenConnect instance remains'; continue }
    if (Approve-Step $dll 'Delete file') {
        try { Remove-Item -LiteralPath $dll -Force -ErrorAction Stop; Add-Action 'SystemDll' $dll 'Removed' }
        catch { Add-Action 'SystemDll' $dll "FAILED (in use until reboot - re-run after reboot): $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# 8. Verify
# ---------------------------------------------------------------------------
$after = Get-ScreenConnectState
$after | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $evid 'state-after.json') -Encoding UTF8
$blocking = Write-VerificationReport $after 'Post-cleanup verification' $survivors

$actions | Export-Csv (Join-Path $out 'actions.csv') -NoTypeInformation -Encoding UTF8
$sum = New-Object System.Text.StringBuilder
[void]$sum.AppendLine('SCREENCONNECT CLEANUP - SUMMARY')
[void]$sum.AppendLine('===============================')
[void]$sum.AppendLine("Computer name : $env:COMPUTERNAME")
[void]$sum.AppendLine("Technician    : $env:USERDOMAIN\$env:USERNAME")
[void]$sum.AppendLine("Date/time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
[void]$sum.AppendLine("Dry run       : $DryRun")
foreach ($t in $targets) {
    [void]$sum.AppendLine('')
    [void]$sum.AppendLine("Client ID         : $($t.ClientId)")
    [void]$sum.AppendLine("Callback hostname : $($t.CallbackHost)")
    [void]$sum.AppendLine("Callback port     : $($t.CallbackPort)")
    [void]$sum.AppendLine("Instance/session  : $($t.SessionId)")
    [void]$sum.AppendLine("Session type      : $($t.SessionType)")
    [void]$sum.AppendLine("Install location  : $($t.InstallFolder)")
    [void]$sum.AppendLine("Service           : $($t.ServiceName)")
}
if ($survivors) { [void]$sum.AppendLine("`r`nLeft in place (not targeted): " + (($survivors | ForEach-Object { "$($_.ClientId) -> $($_.CallbackHost)" }) -join '; ')) }
[void]$sum.AppendLine('')
[void]$sum.AppendLine('Removal actions taken:')
foreach ($a in $actions) { [void]$sum.AppendLine("  [$($a.Step)] $($a.Target) - $($a.Result)") }
[void]$sum.AppendLine('')
[void]$sum.AppendLine("Verification: $(if ($blocking.Count) { 'ITEMS REMAIN' } else { 'PASS' })")
foreach ($r in $blocking) { [void]$sum.AppendLine("  $r") }
[void]$sum.AppendLine('')
[void]$sum.AppendLine('Next steps:')
[void]$sum.AppendLine('  1. Keep the machine OFF the network and reboot.')
[void]$sum.AppendLine('  2. Run: .\ScreenConnect-Cleanup.ps1 -VerifyOnly   (and .\RMM-Triage.ps1 for a full rescan)')
if ($lsaLeft) { [void]$sum.AppendLine('  3. LSA still lists a ScreenConnect package: review evidence\reg-01-Lsa.reg, then re-run with -RemoveLsaEntry.') }
[void]$sum.AppendLine('  - Remove any HideUL files reported by RMM-Triage after evidence is kept.')
[void]$sum.AppendLine('  - Customer: rotate email password first (from a clean device), then banking; enable MFA.')
$sum.ToString() | Set-Content (Join-Path $out 'cleanup-summary.txt') -Encoding UTF8

Write-Host ''
Write-Host $sum.ToString()
$next = if ($DryRun) { 'Review the WHATIF lines in the console/log, then run Cleanup.', 'Cleanup' }
        elseif ($blocking.Count) { 'Some items remain (often locked until reboot). Reboot OFFLINE, then run Cleanup again or Verify.', 'Verify' }
        else { 'Reboot while still OFFLINE, then run Verify.', 'Verify' }
$verdict = if ($DryRun) { 'Amber' } elseif ($blocking.Count) { 'Red' } else { 'Green' }
Write-ToolkitResult -Folder $out -Tool Cleanup -ExitCode ([int][bool]$blocking.Count) -Verdict $verdict -DryRun $DryRun `
    -Instances $targets -TrustedHosts $trustedHosts -Findings @($blocking | ForEach-Object { [pscustomobject]@{ Severity = $(if ($DryRun) { 'Medium' } else { 'High' }); Category = $(if ($DryRun) { 'Present now' } else { 'Remaining' }); Title = $_ } }) `
    -NextStep $next[0] -NextAction $next[1] -SummaryPath (Join-Path $out 'cleanup-summary.txt')
if ($blocking.Count) { exit 1 } else { exit 0 }
