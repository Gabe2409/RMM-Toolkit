#Requires -Version 5.1
<#
.SYNOPSIS
    READ-ONLY triage for Windows machines suspected of a remote-access / RMM
    phishing compromise (current focus: malicious ScreenConnect "Access" clients).

.DESCRIPTION
    This script never changes the machine. It does not stop, delete, disable,
    or modify anything. It collects:
      - ScreenConnect instances and their IOCs (client ID, h= host, p= port,
        s= session ID, e= session type) from service command lines
      - Other RMM / remote-access tools (signatures in config\rmm-signatures.json)
      - Services, processes, network connections of RMM processes
      - Installed programs (incl. entries hidden with SystemComponent=1)
      - Recently installed software, MSI install events, new services (7045)
      - Run keys, Startup folders, scheduled tasks, WMI event subscriptions
      - Local Administrators, Defender state/exclusions/recent detections
      - LSA authentication packages (ScreenConnect auth package check)
      - HideUL / "Hide From Uninstall List" artifacts and odd drops in C:\Users
      - Optional: browser downloads, extensions, notification permissions

    Output goes to C:\Users\Public\RMM-Triage\<COMPUTER>_triage_<timestamp>\

.PARAMETER RecentDays
    Window for "recently installed / recently created" checks. Default 14.

.PARAMETER IncludeBrowser
    Also inspect Chrome/Edge/Brave profiles (downloads, extensions, notifications).

.PARAMETER SkipFileSweep
    Skip the bounded file-name search (HideUL, odd drops). Faster.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\RMM-Triage.ps1 -IncludeBrowser

.NOTES
    Exit code: 0 = nothing notable, 1 = medium findings, 2 = high findings, 13 = config error.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = 'C:\Users\Public\RMM-Triage',
    [ValidateRange(1,365)][int]$RecentDays = 14,
    [switch]$IncludeBrowser,
    [switch]$SkipFileSweep
)

$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'lib\RMMToolkit.Common.psm1') -Force -DisableNameChecking

$ToolkitVersion = '1.0.0'
$out    = Initialize-TriageOutput -Root $OutputRoot -Label 'triage'
$rawDir = Join-Path $out 'raw'; New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
try { $cfg = Import-ToolkitConfig -ConfigDir (Join-Path $PSScriptRoot 'config') }
catch { Write-TriageLog "Config error: $($_.Exception.Message) Fix the config files. Nothing was scanned." -Level ERROR; exit 13 }
$sig    = $cfg.Signatures
$wl     = $cfg.Watchlist
$since  = (Get-Date).AddDays(-$RecentDays)
$findings = New-Object System.Collections.Generic.List[object]

function Save-Raw([string]$Name, $Object) {
    $Object | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $rawDir "$Name.json") -Encoding UTF8
}
function Add-Finding { param($f) $findings.Add($f); Write-TriageLog ("[{0}] {1}: {2}" -f $f.Severity, $f.Category, $f.Title) -Level $(switch ($f.Severity) { 'High' {'HIGH'} 'Medium' {'WARN'} default {'INFO'} }) }
function Test-SuspiciousCommand([string]$cmd) { Test-PatternMatch -Text $cmd -Patterns @($wl.suspiciousCommandPatterns) }

$isAdmin = Test-IsAdmin
Write-TriageLog "RMM-Triage $ToolkitVersion | Host $env:COMPUTERNAME | User $env:USERDOMAIN\$env:USERNAME | Admin=$isAdmin | Window=$RecentDays days"
if (-not $isAdmin) { Write-TriageLog 'Not elevated: services, Defender exclusions, other users and WMI may be incomplete. Re-run as Administrator.' -Level WARN }

# ---------------------------------------------------------------------------
# 1. ScreenConnect instances + IOCs
# ---------------------------------------------------------------------------
Write-TriageLog '--- ScreenConnect ---'
$services  = @(Get-ServiceInventory)
$processes = @(Get-ProcessInventory)
$scInstances = @(Get-ScreenConnectInstances -Services $services)

foreach ($i in $scInstances) {
    $trusted = Test-HostListed $i.CallbackHost @($wl.trustedTenantHosts) -Trusted
    $knownBad = Test-HostListed $i.CallbackHost @($wl.knownBadHosts)
    $sev = if ($knownBad) { 'High' } elseif ($trusted) { 'Info' } elseif ($i.SessionType -eq 'Access') { 'High' } else { 'Medium' }
    $why = if ($knownBad) { 'callback host is on the known-bad list' }
           elseif ($trusted) { 'callback host is on the trusted-tenant list' }
           elseif ($i.SessionType -eq 'Access') { 'unattended (e=Access) client calling an untrusted host' }
           else { 'ScreenConnect client calling an untrusted host' }
    Add-Finding (New-Finding -Category 'ScreenConnect' -Severity $sev -Vendor 'ScreenConnect' `
        -Title ("Client {0} -> {1}:{2} (e={3})" -f $i.ClientId, $i.CallbackHost, $i.CallbackPort, $i.SessionType) `
        -Detail ("Service '{0}' [{1}/{2}] - {3}" -f $i.ServiceName, $i.State, $i.StartMode, $why) -Data $i)
}

# Files on disk, even with no service (half-removed / user-mode clients)
$scFolders = @(Get-ScreenConnectFolders)
foreach ($f in $scFolders) {
    # Match by client ID: one instance also keeps data folders outside its install folder
    $hasService = $scInstances | Where-Object { ($_.ClientId -and (Test-InScope $f @($_.ClientId))) -or ($_.InstallFolder -and $f -ieq $_.InstallFolder) }
    if (-not $hasService) {
        Add-Finding (New-Finding -Category 'ScreenConnect' -Severity 'Medium' -Vendor 'ScreenConnect' `
            -Title "ScreenConnect folder without a matching service: $f" -Data $f)
    }
}

# Auth package DLL + LSA registration
$lsa = Get-LsaAuthenticationPackages
$authDlls = New-Object System.Collections.Generic.List[object]
foreach ($f in $scFolders) {
    Get-ChildItem -LiteralPath $f -Filter 'ScreenConnect.WindowsAuthenticationPackage*.dll' -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $authDlls.Add([pscustomobject]@{ Path = $_.FullName; SHA256 = Get-FileHashSafe $_.FullName; Signature = Get-SignatureSummary $_.FullName }) }
}
foreach ($sysDir in "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64") {
    Get-ChildItem -LiteralPath $sysDir -Filter 'ScreenConnect*.dll' -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $authDlls.Add([pscustomobject]@{ Path = $_.FullName; SHA256 = Get-FileHashSafe $_.FullName; Signature = Get-SignatureSummary $_.FullName }) }
}
$lsaSc = @(@($lsa.AuthenticationPackages) + @($lsa.SecurityPackages) + @($lsa.NotificationPackages) | Where-Object { $_ -match 'ScreenConnect' })
foreach ($d in $authDlls) {
    Add-Finding (New-Finding -Category 'LSA' -Severity 'Medium' -Vendor 'ScreenConnect' -Title "Auth package DLL present: $($d.Path)" -Detail "Signature: $($d.Signature.Status) / $($d.Signature.Signer)" -Data $d)
}
if ($lsaSc) {
    Add-Finding (New-Finding -Category 'LSA' -Severity 'High' -Vendor 'ScreenConnect' -Title ("ScreenConnect registered in LSA packages: {0}" -f ($lsaSc -join ', ')) `
        -Detail 'Do NOT edit by hand. Use the registered uninstaller; ScreenConnect-Cleanup.ps1 handles this with a backup.' -Data $lsa)
}
$unexpectedAuth = @($lsa.AuthenticationPackages | Where-Object { $_ -and ($wl.expectedLsaAuthenticationPackages -notcontains $_) -and $_ -notmatch 'ScreenConnect' })
if ($unexpectedAuth) {
    Add-Finding (New-Finding -Category 'LSA' -Severity 'Medium' -Title ("Non-default LSA authentication packages: {0}" -f ($unexpectedAuth -join ', ')) -Detail 'May be legitimate (smart card, vendor SSO). Verify before changing.' -Data $lsa)
}
Save-Raw 'screenconnect' ([pscustomobject]@{ Instances = $scInstances; Folders = $scFolders; AuthDlls = $authDlls; Lsa = $lsa })

# ---------------------------------------------------------------------------
# 2. Other RMM tools - services, processes, installed apps
# ---------------------------------------------------------------------------
Write-TriageLog '--- Remote-access tools ---'
$rmmHits = New-Object System.Collections.Generic.List[object]
foreach ($s in $services) {
    $v = Find-RmmVendor -Signatures $sig -Text @($s.Name, $s.DisplayName) -Field services
    if (-not $v) { $v = Find-RmmVendor -Signatures $sig -Text @($s.PathName) -Field paths }
    if ($v) { $rmmHits.Add([pscustomobject]@{ Vendor = $v.name; Key = $v.key; Kind = 'Service'; Name = $s.Name; State = $s.State; StartMode = $s.StartMode; Path = $s.PathName }) }
}
$rmmPids = New-Object System.Collections.Generic.List[int]
foreach ($p in $processes) {
    $v = Find-RmmVendor -Signatures $sig -Text @($p.Name) -Field processes
    if (-not $v) { $v = Find-RmmVendor -Signatures $sig -Text @($p.ExecutablePath) -Field paths }
    if ($v) {
        $rmmPids.Add([int]$p.ProcessId)
        $rmmHits.Add([pscustomobject]@{ Vendor = $v.name; Key = $v.key; Kind = 'Process'; Name = $p.Name; State = "PID $($p.ProcessId)"; StartMode = ''; Path = $p.ExecutablePath })
    }
}
$uninstall = @(Get-UninstallEntries)
foreach ($u in $uninstall) {
    $v = Find-RmmVendor -Signatures $sig -Text @($u.DisplayName) -Field names
    if (-not $v) { $v = Find-RmmVendor -Signatures $sig -Text @($u.Publisher) -Field publishers }
    if ($v) {
        $rmmHits.Add([pscustomobject]@{ Vendor = $v.name; Key = $v.key; Kind = 'Installed'; Name = $u.DisplayName; State = $(if ($u.SystemComponent) { 'HIDDEN (SystemComponent=1)' } else { 'Visible' }); StartMode = $u.InstallDateRaw; Path = $u.InstallLocation })
        if ($u.SystemComponent) {
            Add-Finding (New-Finding -Category 'Hiding' -Severity 'High' -Vendor $v.name -Title "$($u.DisplayName) is hidden from Programs and Features" -Detail "SystemComponent=1 on $($u.RegistryPath). Consistent with HideUL-style concealment." -Data $u)
        }
    }
}
# MSI product registrations that have no visible uninstall entry (deleted/moved by a hiding tool)
$msi = @(Get-MsiProductRegistrations)
foreach ($m in $msi) {
    $v = Find-RmmVendor -Signatures $sig -Text @($m.ProductName) -Field names
    if (-not $v) { continue }
    $visible = $uninstall | Where-Object { $_.KeyName -ieq $m.ProductCode -and -not $_.SystemComponent }
    if (-not $visible) {
        Add-Finding (New-Finding -Category 'Hiding' -Severity 'High' -Vendor $v.name -Title "MSI product '$($m.ProductName)' $($m.ProductCode) has no visible uninstall entry" -Detail 'Installer still registered but hidden from Programs list.' -Data $m)
    }
}
$rmmConn = @(Get-ConnectionsForPids -ProcessIds $rmmPids.ToArray())

foreach ($grp in ($rmmHits | Group-Object Vendor)) {
    if ($grp.Name -like 'ScreenConnect*') { continue }   # covered above with IOCs
    $kinds = ($grp.Group | Select-Object -ExpandProperty Kind -Unique) -join ', '
    $names = ($grp.Group | Select-Object -ExpandProperty Name -Unique) -join '; '
    Add-Finding (New-Finding -Category 'RMM' -Severity 'Medium' -Vendor $grp.Name -Title "$($grp.Name) present ($kinds)" `
        -Detail "$names. Confirm with the customer whether this is expected. Not removed automatically." -Data $grp.Group)
}
Save-Raw 'rmm-hits' $rmmHits
Save-Raw 'rmm-connections' $rmmConn

# ---------------------------------------------------------------------------
# 3. Installed programs + recent installs
# ---------------------------------------------------------------------------
Write-TriageLog '--- Installed programs ---'
$uninstall | Where-Object DisplayName | Sort-Object DisplayName |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDateRaw, InstallLocation, SystemComponent, Hive, UninstallString |
    Export-Csv -Path (Join-Path $out 'installed-programs.csv') -NoTypeInformation -Encoding UTF8

$recent = @($uninstall | Where-Object { $_.DisplayName -and $_.InstallDate -and $_.InstallDate -ge $since.Date } | Sort-Object InstallDate -Descending)
foreach ($r in $recent) {
    $unsigned = -not $r.Publisher
    $lure = Test-PatternMatch -Text $r.DisplayName -Patterns @($wl.lureFileNames)
    $sev = if ((Find-RmmVendor -Signatures $sig -Text @($r.DisplayName) -Field names)) { 'Medium' } elseif ($unsigned -or $lure) { 'Low' } else { 'Info' }
    Add-Finding (New-Finding -Category 'RecentInstall' -Severity $sev -Title ("Installed {0:yyyy-MM-dd}: {1} {2}" -f $r.InstallDate, $r.DisplayName, $r.DisplayVersion) -Detail "Publisher: $($r.Publisher)" -Data $r)
}

# Event-log timeline: MSI installs (11707) and new services (7045)
$timeline = New-Object System.Collections.Generic.List[object]
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 11707,1033; StartTime = $since } -ErrorAction Stop |
        ForEach-Object { $timeline.Add([pscustomobject]@{ Time = $_.TimeCreated; Source = 'MsiInstaller'; Id = $_.Id; User = $(try { $_.UserId.Translate([Security.Principal.NTAccount]).Value } catch { [string]$_.UserId }); Message = ($_.Message -replace '\s+',' ') }) }
} catch { }
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -ErrorAction Stop |
        ForEach-Object {
            $msg = $_.Message -replace '\s+',' '
            $timeline.Add([pscustomobject]@{ Time = $_.TimeCreated; Source = 'ServiceInstall'; Id = 7045; User = ''; Message = $msg })
            if ((Find-RmmVendor -Signatures $sig -Text @($msg) -Field any) -or (Test-SuspiciousCommand $msg)) {
                Add-Finding (New-Finding -Category 'Timeline' -Severity 'Medium' -Title ("Service installed {0:yyyy-MM-dd HH:mm}" -f $_.TimeCreated) -Detail $msg)
            }
        }
} catch { }
$timeline | Sort-Object Time | Export-Csv -Path (Join-Path $out 'timeline.csv') -NoTypeInformation -Encoding UTF8

# ScreenConnect client's own Application-log events (connections, sessions)
try {
    $scProviders = @(Get-WinEvent -ListProvider 'ScreenConnect*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $scEvents = $null
    if ($scProviders) {
        $scEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $scProviders; StartTime = (Get-Date).AddDays(-90) } -MaxEvents 2000 -ErrorAction Stop |
            Select-Object TimeCreated, ProviderName, Id, @{n='Message';e={ $_.Message -replace '\s+',' ' }}
    }
    if ($scEvents) { $scEvents | Export-Csv -Path (Join-Path $out 'screenconnect-events.csv') -NoTypeInformation -Encoding UTF8 }
} catch { }

# ---------------------------------------------------------------------------
# 4. Persistence
# ---------------------------------------------------------------------------
Write-TriageLog '--- Persistence ---'
$runKeys = @(Get-RunKeyEntries)
foreach ($r in $runKeys) {
    $v = Find-RmmVendor -Signatures $sig -Text @($r.Command, $r.Name) -Field any
    if ($v) { Add-Finding (New-Finding -Category 'Persistence' -Severity 'Medium' -Vendor $v.name -Title "Run key: $($r.Name)" -Detail "$($r.Location) -> $($r.Command)" -Data $r) }
    elseif (Test-SuspiciousCommand $r.Command) { Add-Finding (New-Finding -Category 'Persistence' -Severity 'High' -Title "Suspicious Run key: $($r.Name)" -Detail "$($r.Location) -> $($r.Command)" -Data $r) }
}
$startup = @(Get-StartupFolderEntries)
foreach ($s in $startup) {
    $txt = "$($s.Name) $($s.Target)"
    $v = Find-RmmVendor -Signatures $sig -Text @($txt) -Field any
    if ($v -or (Test-SuspiciousCommand $txt) -or $s.LastWrite -ge $since) {
        Add-Finding (New-Finding -Category 'Persistence' -Severity $(if ($v -or (Test-SuspiciousCommand $txt)) { 'Medium' } else { 'Low' }) -Vendor $(if ($v) { $v.name } else { '' }) -Title "Startup item: $($s.Name)" -Detail "$($s.Location) -> $($s.Target)" -Data $s)
    }
}
$tasks = @(Get-ScheduledTaskInventory)
foreach ($t in $tasks) {
    $v = Find-RmmVendor -Signatures $sig -Text @($t.TaskName, $t.Actions) -Field any
    $susp = Test-SuspiciousCommand $t.Actions
    $scriptHost = (-not $t.IsMicrosoft) -and (Test-PatternMatch -Text $t.Actions -Patterns @($wl.scriptHosts | ForEach-Object { [regex]::Escape($_) }))
    $isNew = $t.Created -and $t.Created -ge $since -and -not $t.IsMicrosoft
    if ($v -or $susp -or $scriptHost -or $isNew) {
        $sev = if ($susp) { 'High' } elseif ($v -or $scriptHost) { 'Medium' } else { 'Low' }
        Add-Finding (New-Finding -Category 'ScheduledTask' -Severity $sev -Vendor $(if ($v) { $v.name } else { '' }) -Title "$($t.TaskPath)$($t.TaskName)" -Detail "RunAs $($t.RunAs); $($t.Actions)" -Data $t)
    }
}
$wmi = Get-WmiPersistence
foreach ($c in @($wmi.Consumers)) {
    if ($c.Name -in 'SCM Event Log Consumer') { continue }   # Windows default
    Add-Finding (New-Finding -Category 'WMI' -Severity 'High' -Title "WMI event consumer: $($c.Name) ($($c.Class))" -Detail $c.Command -Data $c)
}
Save-Raw 'persistence' ([pscustomobject]@{ RunKeys = $runKeys; Startup = $startup; Tasks = ($tasks | Where-Object { -not $_.IsMicrosoft }); Wmi = $wmi })

# ---------------------------------------------------------------------------
# 5. Accounts + security posture
# ---------------------------------------------------------------------------
Write-TriageLog '--- Accounts & security ---'
$admins = Get-LocalAdminInventory
foreach ($u in @($admins.LocalUsers)) {
    $member = @($admins.Administrators) | Where-Object { $_.SID -eq $u.SID -or $_.Name -like "*\$($u.Name)" }
    if ($member -and $u.Enabled -and $u.SID -notmatch '-500$') {
        Add-Finding (New-Finding -Category 'Accounts' -Severity 'Info' -Title "Local admin: $($u.Name)" -Detail "Last logon $($u.LastLogon); password set $($u.PasswordLastSet)" -Data $u)
    }
}
foreach ($m in @($admins.Administrators)) {
    if (-not $m.SID -and $m.Name) { Add-Finding (New-Finding -Category 'Accounts' -Severity 'Low' -Title "Administrators member (unresolved): $($m.Name)") }
}
$def = Get-DefenderStatus
if ($def.Available) {
    if (-not $def.RealTimeProtectionEnabled) {
        if ($def.AMRunningMode -eq 'Normal') { Add-Finding (New-Finding -Category 'Defender' -Severity 'High' -Title 'Defender real-time protection is OFF' -Data $def) }
        else { Add-Finding (New-Finding -Category 'Defender' -Severity 'Info' -Title "Defender not the active AV (mode: $($def.AMRunningMode))" -Detail 'Another antivirus is likely primary. Confirm it is installed and running.' -Data $def) }
    }
    if ($def.IsTamperProtected -eq $false) { Add-Finding (New-Finding -Category 'Defender' -Severity 'Low' -Title 'Tamper Protection is off' -Data $def) }
    foreach ($ex in @($def.ExclusionPath) + @($def.ExclusionProcess) + @($def.ExclusionExtension)) {
        if ($ex -and $ex -notmatch '^N/A') { Add-Finding (New-Finding -Category 'Defender' -Severity 'Medium' -Title "Defender exclusion: $ex" -Detail 'Verify this was added deliberately.') }
    }
} else {
    Add-Finding (New-Finding -Category 'Defender' -Severity 'Info' -Title 'Defender not queryable (third-party AV or not elevated)' -Data $def)
}
$detections = @(Get-RecentDefenderDetections -Days ([Math]::Max($RecentDays, 30)))
foreach ($d in $detections) { Add-Finding (New-Finding -Category 'Defender' -Severity 'Medium' -Title ("Detection {0:yyyy-MM-dd HH:mm}: ThreatID {1}" -f $d.InitialDetectionTime, $d.ThreatID) -Detail $d.Resources -Data $d) }
Save-Raw 'security' ([pscustomobject]@{ Admins = $admins; Defender = $def; Detections = $detections })

# ---------------------------------------------------------------------------
# 6. Hiding tools (HideUL) and odd drops
# ---------------------------------------------------------------------------
$fileHits = @()
if (-not $SkipFileSweep) {
    Write-TriageLog '--- File sweep (bounded) ---'
    # Deep where users and droppers write; C:\ itself only one level (a deep C:\ crawl walks Windows and repeats the others)
    $hide = @(Find-FilesByPattern -Roots @('C:\Users', 'C:\ProgramData', "$env:SystemRoot\Temp") -NamePatterns @($wl.hidingToolFiles) -Depth 5) +
            @(Find-FilesByPattern -Roots @('C:\') -NamePatterns @($wl.hidingToolFiles) -Depth 1 | Where-Object { $_.Path -notmatch '^C:\\(Users|ProgramData)\\' })
    foreach ($h in $hide) {
        $fileHits += $h
        Add-Finding (New-Finding -Category 'Hiding' -Severity 'High' -Title "Uninstall-list hiding tool artifact: $($h.Path)" -Detail ("Created {0}; SHA256 {1}" -f $h.Created, $(if (-not $h.IsFolder) { Get-FileHashSafe $h.Path })) -Data $h)
    }
    # Executables/archives sitting directly in shared/odd locations (not recursive)
    foreach ($loc in @($wl.suspiciousDropLocations)) {
        if (-not (Test-Path -LiteralPath $loc)) { continue }
        Get-ChildItem -LiteralPath $loc -File -Force -ErrorAction SilentlyContinue |
            Where-Object { (Test-PatternMatch -Text $_.Name -Patterns @($wl.suspiciousDropFileNames)) -and $_.LastWriteTime -ge $since } |
            ForEach-Object {
                $fileHits += $_.FullName
                Add-Finding (New-Finding -Category 'Files' -Severity 'Medium' -Title "Recent executable/archive in $loc : $($_.Name)" -Detail ("Modified {0}; SHA256 {1}" -f $_.LastWriteTime, (Get-FileHashSafe $_.FullName)))
            }
        Get-ChildItem -LiteralPath $loc -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $since -and $loc -eq 'C:\Users' -and $_.Name -notin 'Public','Default','All Users' } |
            ForEach-Object { Add-Finding (New-Finding -Category 'Files' -Severity 'Low' -Title "New folder directly under C:\Users: $($_.Name)" -Detail "Created $($_.CreationTime). Could be a new profile or a dropped tool folder.") }
    }
    Save-Raw 'file-sweep' $fileHits
}

# ---------------------------------------------------------------------------
# 7. Browser indicators (optional)
# ---------------------------------------------------------------------------
if ($IncludeBrowser) {
    Write-TriageLog '--- Browser indicators ---'
    $browserData = New-Object System.Collections.Generic.List[object]
    $profilesRoots = @{ 'Chrome' = 'AppData\Local\Google\Chrome\User Data'; 'Edge' = 'AppData\Local\Microsoft\Edge\User Data'; 'Brave' = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
    foreach ($userDir in (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        # Recent downloads
        $dl = Join-Path $userDir.FullName 'Downloads'
        if (Test-Path -LiteralPath $dl) {
            Get-ChildItem -LiteralPath $dl -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $since } | ForEach-Object {
                $exe  = Test-PatternMatch -Text $_.Name -Patterns @($wl.suspiciousDropFileNames)
                $lure = Test-PatternMatch -Text $_.BaseName -Patterns @($wl.lureFileNames)
                $rmm  = Find-RmmVendor -Signatures $sig -Text @($_.Name) -Field names
                $browserData.Add([pscustomobject]@{ User = $userDir.Name; Kind = 'Download'; Name = $_.Name; Detail = $_.LastWriteTime })
                if ($exe -and ($lure -or $rmm)) {
                    Add-Finding (New-Finding -Category 'Browser' -Severity 'High' -Title "Likely lure download: $($_.FullName)" -Detail ("Modified {0}; SHA256 {1}" -f $_.LastWriteTime, (Get-FileHashSafe $_.FullName)))
                } elseif ($exe) {
                    Add-Finding (New-Finding -Category 'Browser' -Severity 'Low' -Title "Recent executable download: $($_.FullName)" -Detail "Modified $($_.LastWriteTime)")
                }
            }
        }
        foreach ($b in $profilesRoots.Keys) {
            $ud = Join-Path $userDir.FullName $profilesRoots[$b]
            if (-not (Test-Path -LiteralPath $ud)) { continue }
            foreach ($prof in (Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                # Extensions
                $extRoot = Join-Path $prof.FullName 'Extensions'
                foreach ($ext in (Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {
                    $mf = Get-ChildItem -LiteralPath $ext.FullName -Filter manifest.json -Recurse -Depth 1 -ErrorAction SilentlyContinue | Select-Object -First 1
                    $name = $null
                    if ($mf) { try { $name = (Get-Content -Raw -LiteralPath $mf.FullName | ConvertFrom-Json).name } catch { } }
                    $browserData.Add([pscustomobject]@{ User = $userDir.Name; Kind = "$b extension"; Name = $ext.Name; Detail = $name })
                    if ($ext.CreationTime -ge $since) {
                        Add-Finding (New-Finding -Category 'Browser' -Severity 'Low' -Title "$b extension added recently ($($userDir.Name)/$($prof.Name)): $name [$($ext.Name)]" -Detail "Created $($ext.CreationTime)")
                    }
                }
                # Notification permissions
                $prefs = Join-Path $prof.FullName 'Preferences'
                if (Test-Path -LiteralPath $prefs) {
                    try {
                        $j = Get-Content -Raw -LiteralPath $prefs | ConvertFrom-Json
                        $n = $j.profile.content_settings.exceptions.notifications
                        if ($n) {
                            foreach ($site in $n.PSObject.Properties) {
                                if ($site.Value.setting -eq 1) {
                                    $browserData.Add([pscustomobject]@{ User = $userDir.Name; Kind = "$b notification allowed"; Name = $site.Name; Detail = $prof.Name })
                                    Add-Finding (New-Finding -Category 'Browser' -Severity 'Low' -Title "$b notifications allowed for $($site.Name)" -Detail "$($userDir.Name)/$($prof.Name) - review; push-notification spam is a common follow-on.")
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
    }
    $browserData | Export-Csv -Path (Join-Path $out 'browser.csv') -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------------------
# 8. Reports
# ---------------------------------------------------------------------------
Write-TriageLog '--- Writing reports ---'
$findings | Select-Object Severity, Category, Vendor, Title, Detail |
    Export-Csv -Path (Join-Path $out 'findings.csv') -NoTypeInformation -Encoding UTF8
Save-Raw 'findings' $findings

$high   = @($findings | Where-Object Severity -eq 'High')
$medium = @($findings | Where-Object Severity -eq 'Medium')
$persist = @($findings | Where-Object { $_.Category -in 'Persistence','ScheduledTask','WMI','Hiding','LSA' -and $_.Severity -in 'High','Medium' })
$otherRmm = @($findings | Where-Object { $_.Category -eq 'RMM' } | ForEach-Object { $_.Title })
# Only these mean "someone had remote access"; other Highs (WMI, Run keys) get the generic wording
$remoteHigh = @($high | Where-Object { $_.Category -in 'ScreenConnect','RMM','Hiding','LSA' })
$joinOrNone = { param($a) if (@($a).Count) { (@($a) -join "`r`n    ") } else { 'none' } }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('RMM INCIDENT TRIAGE - SUMMARY')
[void]$sb.AppendLine('=============================')
[void]$sb.AppendLine("Computer name   : $env:COMPUTERNAME")
[void]$sb.AppendLine("Run by          : $env:USERDOMAIN\$env:USERNAME (admin: $isAdmin)")
[void]$sb.AppendLine("Logged-on users : " + ((@(Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName | Where-Object { $_ }) -join ', '))
[void]$sb.AppendLine("Date/time       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
[void]$sb.AppendLine("Toolkit version : $ToolkitVersion (signatures $($sig.version))")
[void]$sb.AppendLine("Verdict         : $(if ($high) { 'COMPROMISE INDICATORS FOUND' } elseif ($medium) { 'REVIEW REQUIRED' } else { 'No significant indicators' })  [High=$($high.Count) Medium=$($medium.Count)]")
[void]$sb.AppendLine('')
if ($scInstances.Count -eq 0) {
    [void]$sb.AppendLine('ScreenConnect   : no client service found')
} else {
    $n = 0
    foreach ($i in $scInstances) {
        $n++
        [void]$sb.AppendLine("ScreenConnect instance #$n")
        [void]$sb.AppendLine("  Client ID         : $($i.ClientId)")
        [void]$sb.AppendLine("  Callback hostname : $($i.CallbackHost)")
        [void]$sb.AppendLine("  Callback port     : $($i.CallbackPort)")
        [void]$sb.AppendLine("  Instance/session  : $($i.SessionId)")
        [void]$sb.AppendLine("  Session type (e=) : $($i.SessionType)")
        [void]$sb.AppendLine("  Install location  : $($i.InstallFolder)")
        [void]$sb.AppendLine("  Service           : $($i.ServiceName) [$($i.State)/$($i.StartMode)]")
        if ($i.CustomProps) { [void]$sb.AppendLine("  Custom props (c=) : $(@($i.CustomProps) -join ' | ')") }
    }
}
if ($scFolders) { [void]$sb.AppendLine("ScreenConnect folders:`r`n    " + (& $joinOrNone $scFolders)) }
$conns = @($rmmConn | ForEach-Object { "PID $($_.OwningProcess) -> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]" })
[void]$sb.AppendLine("RMM network connections:`r`n    " + (& $joinOrNone $conns))
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Services found:`r`n    " + (& $joinOrNone ($rmmHits | Where-Object Kind -eq 'Service' | ForEach-Object { "$($_.Name) [$($_.State)/$($_.StartMode)]" })))
[void]$sb.AppendLine("Other RMM tools found:`r`n    " + (& $joinOrNone $otherRmm))
[void]$sb.AppendLine("Persistence / hiding found:`r`n    " + (& $joinOrNone ($persist | ForEach-Object { "[$($_.Severity)] $($_.Title)" })))
[void]$sb.AppendLine("Removal actions taken : none (triage is read-only)")
[void]$sb.AppendLine("Verification results  : n/a - run ScreenConnect-Cleanup.ps1 -VerifyOnly after remediation")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('ALL HIGH / MEDIUM FINDINGS')
foreach ($f in ($high + $medium)) { [void]$sb.AppendLine("  [$($f.Severity)] $($f.Category): $($f.Title)"); if ($f.Detail) { [void]$sb.AppendLine("           $($f.Detail)") } }
[void]$sb.AppendLine('')
[void]$sb.AppendLine('RECOMMENDED FOLLOW-UP')
$rec = New-Object System.Collections.Generic.List[string]
if ($scInstances | Where-Object { $_.SessionType -eq 'Access' }) {
    $rec.Add('Disconnect the machine from the network before remediation (unplug / disable Wi-Fi).')
    $rec.Add('Run ScreenConnect-Cleanup.ps1 as Administrator, then reboot OFFLINE and run it again with -VerifyOnly.')
}
if ($otherRmm) { $rec.Add('Ask the customer about each other remote-access tool. Remove only those they did not install (RMM-Cleanup is technician-driven).') }
if ($findings | Where-Object Category -eq 'Hiding') { $rec.Add('Hiding tool / hidden uninstall entries present: treat as deliberate attacker activity; remove the HideUL files after evidence is preserved.') }
if ($remoteHigh) {
    $rec.Add('From a CLEAN device: change the email password first (the phishing came from a compromised contact), then banking, then everything else. Enable MFA.')
    $rec.Add('Review email forwarding rules, recovery phone/email and signed-in sessions on the email account.')
    $rec.Add('Assume anything typed or viewed during the remote session was exposed. Contact the bank if financial sites were opened; watch for fraudulent transfers.')
    $rec.Add('Check for new local accounts, changed passwords, and browser-saved passwords; consider clearing saved passwords after rotating them.')
    if ($scInstances) { $rec.Add('Report the callback hostname to ConnectWise abuse (ScreenConnect cloud relays can be taken down).') }
}
if ($high) { $rec.Add('Run a full Defender (or equivalent) scan and an offline scan after cleanup.') }
if (-not $rec.Count) { $rec.Add('No action required based on this scan. Keep this report on file.') }
foreach ($r in $rec) { [void]$sb.AppendLine("  - $r") }
[void]$sb.AppendLine('')
[void]$sb.AppendLine("Files: findings.csv, installed-programs.csv, timeline.csv, technician-log.txt, raw\*.json")
$sb.ToString() | Set-Content -Path (Join-Path $out 'incident-summary.txt') -Encoding UTF8

# Customer-facing plain-language report
$cust = New-Object System.Text.StringBuilder
[void]$cust.AppendLine("Computer check - $env:COMPUTERNAME - $(Get-Date -Format 'MMMM d, yyyy')")
[void]$cust.AppendLine('')
if ($remoteHigh) {
    [void]$cust.AppendLine('What we found')
    [void]$cust.AppendLine('Your computer had remote-access software installed that lets someone else connect to it and control it without asking you first. This usually happens after clicking a link in an email that looked like it came from someone you know (for example an invitation), then following instructions to "verify" or "download" something.')
    if ($scInstances) { [void]$cust.AppendLine('The software found was a remote-support program called ScreenConnect, set up to connect to a server that does not belong to you or to us.') }
    if ($otherRmm)    { [void]$cust.AppendLine("We also found other remote-access programs: $((@($findings | Where-Object Category -eq 'RMM' | ForEach-Object Vendor) | Select-Object -Unique) -join ', '). We will confirm with you whether you use these before removing anything.") }
    [void]$cust.AppendLine('')
    [void]$cust.AppendLine('What you should do')
    [void]$cust.AppendLine('  1. Change your email password from a different, safe device, and turn on two-step verification.')
    [void]$cust.AppendLine('  2. Change passwords for banking and any site you used on this computer recently.')
    [void]$cust.AppendLine('  3. Call your bank if you were logged in to online banking while the computer could have been accessed.')
    [void]$cust.AppendLine('  4. Let your contacts know your email may have sent them a fake invitation, so they do not click it.')
    [void]$cust.AppendLine('  5. Never install software or paste commands because a web page or "CAPTCHA" tells you to.')
} elseif ($high -or $medium) {
    [void]$cust.AppendLine('We found a few items to review with you, such as remote-access programs or settings that may or may not be expected. Nothing has been changed yet.')
} else {
    [void]$cust.AppendLine('We did not find signs of unwanted remote-access software on this computer.')
}
$cust.ToString() | Set-Content -Path (Join-Path $out 'customer-summary.txt') -Encoding UTF8

Write-TriageLog "Done. High=$($high.Count) Medium=$($medium.Count). Summary: $(Join-Path $out 'incident-summary.txt')" -Level OK
Write-Host ''
Write-Host (Get-Content -Raw (Join-Path $out 'incident-summary.txt'))

$code = if ($high) { 2 } elseif ($medium) { 1 } else { 0 }
$untrusted = @($scInstances | Where-Object { -not (Test-HostListed $_.CallbackHost @($wl.trustedTenantHosts) -Trusted) })
$next = if ($untrusted) { 'Disconnect the network, then run Cleanup dry run.', 'DryRun' }
        elseif ($high)  { 'Review the High findings below; they need manual removal.', '' }
        elseif ($medium) { 'Review the findings with the customer.', '' }
        else { 'Nothing to do. Keep the report on file.', '' }
Write-ToolkitResult -Folder $out -Tool Triage -ExitCode $code -Verdict @('Green', 'Amber', 'Red')[$code] `
    -Instances $scInstances -TrustedHosts @($wl.trustedTenantHosts) -Connections $rmmConn -Findings ($high + $medium) `
    -NextStep $next[0] -NextAction $next[1] -SummaryPath (Join-Path $out 'incident-summary.txt')
exit $code
