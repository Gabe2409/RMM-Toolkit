#Requires -Version 5.1
<#
    RMMToolkit.Common.psm1
    ----------------------
    Shared, READ-ONLY helpers for the RMM incident toolkit.

    Nothing in this module changes system state. Every function here only
    reads (registry, CIM/WMI, files, event logs) and returns objects.
    Destructive actions live exclusively in the dedicated cleanup scripts.
#>

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Logging / output folder
# ---------------------------------------------------------------------------

$script:LogFile = $null

function Initialize-TriageOutput {
    [CmdletBinding()]
    param(
        [string]$Root = 'C:\Users\Public\RMM-Triage',
        [string]$Label = 'triage'
    )
    $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $folder = Join-Path $Root ('{0}_{1}_{2}' -f $env:COMPUTERNAME, $Label, $stamp)
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $script:LogFile = Join-Path $folder 'technician-log.txt'
    Write-TriageLog "Output folder: $folder"
    return $folder
}

function Write-TriageLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','HIGH','ACTION','OK','ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-6}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'HIGH'   { 'Red' }
        'ERROR'  { 'Red' }
        'WARN'   { 'Yellow' }
        'ACTION' { 'Cyan' }
        'OK'     { 'Green' }
        default  { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Vendor = '',
        [string]$Detail = '',
        $Data = $null
    )
    [pscustomobject][ordered]@{
        Category = $Category
        Severity = $Severity
        Vendor   = $Vendor
        Title    = $Title
        Detail   = $Detail
        Data     = $Data
    }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# Config / matching
# ---------------------------------------------------------------------------

function Import-ToolkitConfig {
    [CmdletBinding()]
    param([string]$ConfigDir = (Join-Path $PSScriptRoot '..\config'))
    # A missing or broken config must stop the run: empty lists silently disable detections
    $ErrorActionPreference = 'Stop'
    $sig = Get-Content -Raw -Path (Join-Path $ConfigDir 'rmm-signatures.json') | ConvertFrom-Json
    $ioc = Get-Content -Raw -Path (Join-Path $ConfigDir 'ioc-watchlist.json')  | ConvertFrom-Json
    # Strip "_comment" placeholder strings from lists
    foreach ($p in 'knownBadHosts','trustedTenantHosts') {
        $ioc.$p = @($ioc.$p | Where-Object { $_ -and $_ -notlike '_comment*' })
    }
    [pscustomobject]@{ Signatures = $sig; Watchlist = $ioc }
}

function Test-PatternMatch {
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Text) -or -not $Patterns) { return $false }
    foreach ($p in $Patterns) {
        if ($p -and $Text -match $p) { return $true }
    }
    return $false
}

function Test-HostListed {
    <#
        Default (known-bad lists): exact or regex match - broad on purpose.
        -Trusted: exact or wildcard (*.mymsp.com) only, so a lookalike host such as
        relay.mymsp.com.evil.net or relay1mymsp.com can never pass as trusted.
    #>
    param([string]$HostName, [string[]]$List, [switch]$Trusted)
    if (-not $HostName) { return $false }
    foreach ($e in $List) {
        if (-not $e) { continue }
        if ($Trusted) { if ($HostName -like $e) { return $true } }
        elseif ($HostName -ieq $e -or $HostName -match $e) { return $true }
    }
    return $false
}

function Test-InScope {
    # True if $Text belongs to one of the targeted client IDs (or all, if $Ids is empty)
    param([string]$Text, [string[]]$Ids)
    if (-not $Ids) { return $true }
    foreach ($id in $Ids) { if ($Text -match [regex]::Escape("($id)")) { return $true } }
    return $false
}

function Find-RmmVendor {
    <#
        Returns the first vendor whose signatures match any of the supplied
        strings for the given field type, or $null.
        Field: names | services | processes | paths | publishers | any
    #>
    param(
        [Parameter(Mandatory)]$Signatures,
        [string[]]$Text,
        [ValidateSet('names','services','processes','paths','publishers','any')][string]$Field = 'any'
    )
    $Text = @($Text | Where-Object { $_ })
    if (-not $Text) { return $null }
    foreach ($v in $Signatures.vendors) {
        $fields = if ($Field -eq 'any') { 'names','services','processes','paths','publishers' } else { @($Field) }
        foreach ($f in $fields) {
            $pats = @($v.$f)
            foreach ($t in $Text) {
                if (Test-PatternMatch -Text $t -Patterns $pats) { return $v }
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# ScreenConnect IOC parsing (pure functions - unit tested)
# ---------------------------------------------------------------------------

function ConvertFrom-ScreenConnectCommandLine {
    <#
        Parses a ScreenConnect client service command line / ImagePath, e.g.

        "C:\Program Files (x86)\ScreenConnect Client (1a2b3c4d5e6f7a8b)\ScreenConnect.ClientService.exe"
          "?e=Access&y=Guest&h=relay.example.com&p=8041&s=0f1e...&k=BgIAAAC...&c=&c=&t="

        Returns the decoded parameters plus the client/instance ID taken from
        the "ScreenConnect Client (xxxx)" folder or service name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$CommandLine)

    $result = [ordered]@{
        ClientId        = $null   # thumbprint in "ScreenConnect Client (....)"
        Executable      = $null
        InstallFolder   = $null
        SessionType     = $null   # e=  (Access = unattended, Support = one-off, Meeting)
        ClientType      = $null   # y=
        CallbackHost    = $null   # h=
        CallbackPort    = $null   # p=
        SessionId       = $null   # s=
        PublicKeyPrefix = $null   # k=  (first chars only, it is long)
        CustomProperties= @()     # c=
        RawQuery        = $null
    }
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return [pscustomobject]$result }

    if ($CommandLine -match 'ScreenConnect Client \(([0-9a-fA-F]+)\)') { $result.ClientId = $Matches[1].ToLower() }

    if ($CommandLine -match '^\s*"?([^"]+?\.exe)"?') {
        $result.Executable = $Matches[1]
        $ix = $result.Executable.LastIndexOf('\')
        if ($ix -gt 0) { $result.InstallFolder = $result.Executable.Substring(0, $ix) }
    }

    $q = $null
    if ($CommandLine -match '\?([^"\s]*=[^"\s]*)') { $q = $Matches[1] }
    if ($q) {
        $result.RawQuery = $q
        $custom = New-Object System.Collections.Generic.List[string]
        foreach ($pair in ($q -split '&')) {
            if (-not $pair) { continue }
            $kv  = $pair -split '=', 2
            $key = $kv[0]
            $val = if ($kv.Count -gt 1) { [Uri]::UnescapeDataString(($kv[1] -replace '\+',' ')) } else { '' }
            switch -CaseSensitive ($key) {
                'e' { $result.SessionType  = $val }
                'y' { $result.ClientType   = $val }
                'h' { $result.CallbackHost = $val }
                'p' { $result.CallbackPort = $val }
                's' { $result.SessionId    = $val }
                'k' { if ($val) { $result.PublicKeyPrefix = $val.Substring(0, [Math]::Min(32, $val.Length)) } }
                'c' { if ($val) { $custom.Add($val) } }
            }
        }
        $result.CustomProperties = @($custom)
    }
    [pscustomobject]$result
}

function ConvertFrom-PackedGuid {
    <#
        Converts a Windows Installer "packed" GUID (as used under
        HKLM\SOFTWARE\Classes\Installer\Products) back to a normal
        product code {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
    #>
    param([Parameter(Mandatory)][string]$Packed)
    if ($Packed -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $rev = { param($s) -join ($s.ToCharArray()[($s.Length-1)..0]) }
    $swap = { param($s) $o=''; for ($i=0; $i -lt $s.Length; $i+=2) { $o += $s[$i+1]; $o += $s[$i] }; $o }
    $p = $Packed.ToUpper()
    $g = '{0}-{1}-{2}-{3}-{4}' -f (& $rev $p.Substring(0,8)), (& $rev $p.Substring(8,4)), (& $rev $p.Substring(12,4)),
                                  (& $swap $p.Substring(16,4)), (& $swap $p.Substring(20,12))
    return '{' + $g + '}'
}

function ConvertFrom-InstallDate {
    param([string]$Value)
    if ($Value -match '^\d{8}$') {
        try { return [datetime]::ParseExact($Value, 'yyyyMMdd', $null) } catch { }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Installed programs
# ---------------------------------------------------------------------------

function Get-UninstallEntries {
    <#
        Reads uninstall entries from HKLM (64/32-bit), HKCU and every loaded
        user hive under HKU. Includes entries hidden with SystemComponent=1
        (a common trick, and what hiding tools like HideUL abuse) and flags them.
    #>
    [CmdletBinding()]
    param()

    $roots = New-Object System.Collections.Generic.List[string]
    $roots.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $roots.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    # No HKCU root: the current user's hive is already loaded under HKU, reading both listed it twice
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object { $roots.Add("Registry::HKEY_USERS\$($_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") }
    } catch { }

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if (-not $p) { continue }
            $name = $p.PSObject.Properties['DisplayName']
            $name = if ($name) { $name.Value } else { $null }

            $get = { param($n) $x = $p.PSObject.Properties[$n]; if ($x) { $x.Value } else { $null } }
            $installDateRaw = & $get 'InstallDate'
            [pscustomobject][ordered]@{
                DisplayName      = $name
                DisplayVersion   = & $get 'DisplayVersion'
                Publisher        = & $get 'Publisher'
                InstallDate      = ConvertFrom-InstallDate $installDateRaw
                InstallDateRaw   = $installDateRaw
                InstallLocation  = & $get 'InstallLocation'
                UninstallString  = & $get 'UninstallString'
                QuietUninstall   = & $get 'QuietUninstallString'
                SystemComponent  = [bool](& $get 'SystemComponent')
                KeyName          = $key.PSChildName
                RegistryPath     = $key.Name
                Hive             = ($root -split '\\')[0]
            }
        }
    }
}

function Get-MsiProductRegistrations {
    <#
        Windows Installer's own product registry (independent of the
        Uninstall key). Useful when the Uninstall entry was hidden/removed.
    #>
    $root = 'HKLM:\SOFTWARE\Classes\Installer\Products'
    if (-not (Test-Path $root)) { return }
    foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
        $pn = if ($p -and $p.PSObject.Properties['ProductName']) { $p.ProductName } else { $null }
        if (-not $pn) { continue }
        [pscustomobject]@{
            ProductName = $pn
            PackedGuid  = $k.PSChildName
            ProductCode = ConvertFrom-PackedGuid $k.PSChildName
        }
    }
}

# ---------------------------------------------------------------------------
# Services / processes / network
# ---------------------------------------------------------------------------

function Get-ServiceInventory {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId, Description
}

function Get-ProcessInventory {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
}

function Get-ConnectionsForPids {
    param([int[]]$ProcessIds)
    if (-not $ProcessIds) { return }
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return }
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $ProcessIds -contains $_.OwningProcess -and $_.RemoteAddress -notin '0.0.0.0','::','127.0.0.1','::1' } |
        Select-Object OwningProcess, State, LocalAddress, LocalPort, RemoteAddress, RemotePort
}

function Get-ScreenConnectInstances {
    <#
        Every ScreenConnect client instance discoverable from services,
        with parsed IOC data. Multiple instances on one machine are common
        (attacker + legitimate MSP), so this returns a list.
    #>
    [CmdletBinding()]
    param($Services = (Get-ServiceInventory))
    foreach ($svc in $Services) {
        if (($svc.Name -match 'ScreenConnect') -or ($svc.PathName -match 'ScreenConnect\.ClientService\.exe')) {
            $ioc = ConvertFrom-ScreenConnectCommandLine -CommandLine ([string]$svc.PathName)
            if (-not $ioc.ClientId -and $svc.Name -match '\(([0-9a-fA-F]+)\)') { $ioc.ClientId = $Matches[1].ToLower() }
            [pscustomobject][ordered]@{
                ServiceName   = $svc.Name
                DisplayName   = $svc.DisplayName
                State         = $svc.State
                StartMode     = $svc.StartMode
                RunAs         = $svc.StartName
                ProcessId     = $svc.ProcessId
                ImagePath     = $svc.PathName
                ClientId      = $ioc.ClientId
                SessionType   = $ioc.SessionType
                ClientType    = $ioc.ClientType
                CallbackHost  = $ioc.CallbackHost
                CallbackPort  = $ioc.CallbackPort
                SessionId     = $ioc.SessionId
                InstallFolder = $ioc.InstallFolder
                Executable    = $ioc.Executable
                CustomProps   = $ioc.CustomProperties
                PublicKeyHead = $ioc.PublicKeyPrefix
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

function Get-RunKeyEntries {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object {
                $keys += "Registry::HKEY_USERS\$($_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                $keys += "Registry::HKEY_USERS\$($_.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            }
    } catch { }
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            [pscustomobject]@{ Location = $k; Name = $pr.Name; Command = [string]$pr.Value }
        }
    }
}

function Get-StartupFolderEntries {
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $folders += Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($f in $folders) {
        if (-not (Test-Path $f)) { continue }
        foreach ($item in (Get-ChildItem $f -File -Force -ErrorAction SilentlyContinue)) {
            if ($item.Name -eq 'desktop.ini') { continue }
            $target = $null
            if ($shell -and $item.Extension -eq '.lnk') {
                try { $l = $shell.CreateShortcut($item.FullName); $target = ('{0} {1}' -f $l.TargetPath, $l.Arguments).Trim() } catch { }
            }
            [pscustomobject]@{ Location = $f; Name = $item.Name; Target = $target; LastWrite = $item.LastWriteTime }
        }
    }
}

function Get-ScheduledTaskInventory {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actions = @($t.Actions | ForEach-Object {
            $exe = $_.PSObject.Properties['Execute']; $arg = $_.PSObject.Properties['Arguments']
            (('{0} {1}' -f ($(if ($exe) { $exe.Value }), $(if ($arg) { $arg.Value }))).Trim())
        }) -join ' || '
        $created = $null
        try { if ($t.Date) { $created = [datetime]$t.Date } } catch { }
        [pscustomobject][ordered]@{
            TaskPath = $t.TaskPath
            TaskName = $t.TaskName
            State    = [string]$t.State
            Author   = $t.Author
            RunAs    = $t.Principal.UserId
            Created  = $created
            Actions  = $actions
            IsMicrosoft = ($t.TaskPath -like '\Microsoft\*')
            NetworkTrigger = @($t.Triggers | Where-Object { $_ -and $_.CimClass.CimClassName -eq 'MSFT_TaskEventTrigger' -and (Test-NetworkEventTrigger $_.Subscription) }).Count -gt 0
            WaitsForNetwork = [bool]$t.Settings.RunOnlyIfNetworkAvailable
        }
    }
}

function Test-NetworkEventTrigger {
    # True when a task's event subscription fires on network connect (Wi-Fi joined, internet detected, DHCP lease)
    param([string]$Subscription)
    return $Subscription -match 'Microsoft-Windows-(NetworkProfile|NCSI|WLAN-AutoConfig|Dhcp)'
}

function Get-NetworkTriggeredServices {
    # Services Windows starts when the PC gets an IP address (SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY = 2)
    foreach ($key in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue)) {
        $info = Join-Path $key.PSPath 'TriggerInfo'
        if (-not (Test-Path -LiteralPath $info)) { continue }
        $types = @(Get-ChildItem -LiteralPath $info -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Type })
        if ($types -contains 2) { $key.PSChildName }
    }
}

function Test-WinlogonValue {
    # Shell / Userinit replaced = a full-screen blocker or backdoor runs at every logon instead of the desktop
    param([string]$Name, [string]$Value)
    $v = $Value.Trim()
    if ($Name -eq 'Shell') { return $v -match '^([A-Za-z]:\\Windows\\)?explorer(\.exe)?$' }
    return $v -match '^([A-Za-z]:\\Windows\\system32\\)?userinit(\.exe)?,?$'
}

function Get-LogonHijackEntries {
    # Winlogon Shell/Userinit that aren't the Windows defaults, and any IFEO "Debugger" redirect
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object { $keys += "Registry::HKEY_USERS\$($_.PSChildName)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" }
    foreach ($k in $keys) {
        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($n in 'Shell', 'Userinit') {
            $prop = $p.PSObject.Properties[$n]
            if ($prop -and $prop.Value -and -not (Test-WinlogonValue $n ([string]$prop.Value))) {
                [pscustomobject]@{ Kind = 'Winlogon'; Name = $n; Value = [string]$prop.Value; Location = $k }
            }
        }
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($s in (Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue)) {
        $d = (Get-ItemProperty -LiteralPath $s.PSPath -ErrorAction SilentlyContinue).PSObject.Properties['Debugger']
        if ($d -and $d.Value) { [pscustomobject]@{ Kind = 'IFEO'; Name = $s.PSChildName; Value = [string]$d.Value; Location = $s.Name } }
    }
}

function Get-CommandTargetPath {
    # The file a command line really runs. For script hosts (powershell, wscript, rundll32...) that is the script/DLL it is handed.
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim()) -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    $p = if ($c -match '^"([^"]+)"') { $Matches[1] }
         elseif ($c -match '^(.+?\.(exe|com|scr|bat|cmd|ps1|vbs|vbe|js|jse|hta|msi|dll|sys))(?=[\s,]|$)') { $Matches[1] }
         else { ($c -split '\s')[0] }
    if (($p -replace '.*\\', '') -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$') {
        $rest = $c.Substring($c.IndexOf($p) + $p.Length)
        if ($rest -match '([A-Za-z]:\\[^"|<>*?]+?\.(ps1|vbs|vbe|js|jse|bat|cmd|hta|dll|exe))(?=["\s,]|$)') { return $Matches[1] }
    }
    return $p
}

function Get-AutostartRating {
    # Pure decision: how worrying is this auto-starting file? Severity '' = nothing to report.
    param([string]$Path, [datetime]$Created, [string]$SignatureStatus, [datetime]$Since)
    $inWindows = $Path -match '^[A-Za-z]:\\Windows\\' -and $Path -notmatch '^[A-Za-z]:\\Windows\\Temp\\'
    $standard  = $inWindows -or $Path -match '^[A-Za-z]:\\Program Files( \(x86\))?\\'
    $unsigned  = $SignatureStatus -ne 'Valid'
    $sev = ''; $why = ''
    if ($Created -ge $Since) {
        if ($unsigned) { $sev = 'Medium'; $why = 'added recently and not signed' }
        elseif (-not $inWindows) { $sev = 'Low'; $why = 'added recently' }
    } elseif ($unsigned -and -not $standard) { $sev = 'Medium'; $why = 'not signed, in a user-writable folder' }
    [pscustomobject]@{ Severity = $sev; Why = $why; Standard = $standard }
}

function Get-FileFacts {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $null }
    $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $i) { return $null }
    $s = Get-SignatureSummary $Path
    [pscustomobject]@{ Created = $i.CreationTime; Status = $s.Status; Signer = $s.Signer }
}

function Get-RecentProgramFiles {
    # Programs and scripts created since -Since in the places malware drops them (bounded depth, known-noisy trees skipped)
    param([datetime]$Since, [string[]]$NamePatterns, [string]$ExcludePattern, [int]$Depth = 3, [int]$MaxResults = 300)
    $roots = @("$env:ProgramData", 'C:\Users\Public', "$env:SystemRoot\Temp")
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($sub in 'Roaming', 'Local', 'LocalLow') { $roots += Join-Path $u.FullName "AppData\$sub" }
    }
    $n = 0
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -Depth $Depth -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.CreationTime -lt $Since -or $f.FullName -match $ExcludePattern -or -not (Test-PatternMatch -Text $f.Name -Patterns $NamePatterns)) { continue }
            $s = Get-SignatureSummary $f.FullName
            [pscustomobject]@{ Path = $f.FullName; Folder = $f.DirectoryName; Name = $f.Name; Created = $f.CreationTime; Signature = $s.Status; Signer = $s.Signer }
            if (++$n -ge $MaxResults) { return }
        }
    }
}

function Get-RecentOpenedItems {
    # Files and folders each user opened, from Windows' own Recent shortcuts. Names only; the files are not read.
    param([datetime]$Since, [int]$MaxResults = 1000)
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    $n = 0
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        $dir = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
        if (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) { continue }
        foreach ($l in (Get-ChildItem -LiteralPath $dir -Filter *.lnk -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $Since } | Sort-Object LastWriteTime -Descending)) {
            $target = ''
            if ($shell) { try { $target = $shell.CreateShortcut($l.FullName).TargetPath } catch { } }
            [pscustomobject]@{ User = $u.Name; Item = $l.BaseName; Target = $target; Opened = $l.LastWriteTime }
            if (++$n -ge $MaxResults) { return }
        }
    }
}

function Get-WmiPersistence {
    $ns = 'root\subscription'
    $out = [ordered]@{ Filters = @(); Consumers = @(); Bindings = @() }
    try {
        $out.Filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop |
            Select-Object Name, Query, QueryLanguage, EventNamespace)
        $out.Consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Class   = $_.CimClass.CimClassName
                Name    = $_.Name
                Command = if ($_.CimInstanceProperties['CommandLineTemplate']) { $_.CommandLineTemplate }
                          elseif ($_.CimInstanceProperties['ScriptText']) { $_.ScriptText }
                          elseif ($_.CimInstanceProperties['ScriptFileName']) { $_.ScriptFileName } else { $null }
            }
        })
        $out.Bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Filter = [string]$_.Filter; Consumer = [string]$_.Consumer } })
    } catch {
        $out['Error'] = $_.Exception.Message
    }
    [pscustomobject]$out
}

# ---------------------------------------------------------------------------
# Accounts / security config / LSA
# ---------------------------------------------------------------------------

function Get-LocalAdminInventory {
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object Name, ObjectClass, PrincipalSource, @{n='SID';e={[string]$_.SID}})
    } catch {
        # Fallback for broken Get-LocalGroupMember (orphaned SIDs) - parse net.exe output
        $grp = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $raw = & net.exe localgroup "$grp" 2>$null
        $inList = $false
        foreach ($l in $raw) {
            if ($l -match '^-{5,}') { $inList = $true; continue }
            if ($inList -and $l -and $l -notmatch 'command completed') { $members += [pscustomobject]@{ Name = $l.Trim(); ObjectClass = '?'; PrincipalSource = '?'; SID = $null } }
        }
    }
    $users = @()
    try {
        $users = @(Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, @{n='SID';e={[string]$_.SID}})
    } catch { }
    [pscustomobject]@{ Administrators = $members; LocalUsers = $users }
}

function Get-DefenderStatus {
    $o = [ordered]@{ Available = $false }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return [pscustomobject]$o }
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        $p = Get-MpPreference -ErrorAction Stop
        $o.Available                 = $true
        # 'Normal' = Defender is the active AV; 'Passive'/'EDR Block Mode' = another AV is primary
        $o.AMRunningMode             = if ($s.PSObject.Properties['AMRunningMode']) { [string]$s.AMRunningMode } else { $null }
        $o.AMServiceEnabled          = $s.AMServiceEnabled
        $o.AntivirusEnabled          = $s.AntivirusEnabled
        $o.RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
        $o.BehaviorMonitorEnabled    = $s.BehaviorMonitorEnabled
        $o.IsTamperProtected         = $s.IsTamperProtected
        $o.SignatureAge              = $s.AntivirusSignatureAge
        $o.SignatureLastUpdated      = $s.AntivirusSignatureLastUpdated
        $o.DisableRealtimeMonitoring = $p.DisableRealtimeMonitoring
        $o.ExclusionPath             = @($p.ExclusionPath)
        $o.ExclusionProcess          = @($p.ExclusionProcess)
        $o.ExclusionExtension        = @($p.ExclusionExtension)
        $o.PUAProtection             = $p.PUAProtection
    } catch { $o.Error = $_.Exception.Message }
    [pscustomobject]$o
}

function Get-RecentDefenderDetections {
    param([int]$Days = 30)
    if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) { return }
    $since = (Get-Date).AddDays(-$Days)
    Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { $_.InitialDetectionTime -ge $since } |
        Select-Object InitialDetectionTime, ThreatID, ActionSuccess, @{n='Resources';e={ @($_.Resources) -join '; ' }}
}

function Get-LsaAuthenticationPackages {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    $get = { param($n) if ($p -and $p.PSObject.Properties[$n]) { @($p.$n) } else { @() } }
    [pscustomobject][ordered]@{
        AuthenticationPackages = & $get 'Authentication Packages'
        SecurityPackages       = & $get 'Security Packages'
        NotificationPackages   = & $get 'Notification Packages'
        RunAsPPL               = if ($p -and $p.PSObject.Properties['RunAsPPL']) { $p.RunAsPPL } else { $null }
    }
}

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

function Find-FilesByPattern {
    <#
        Bounded, read-only file name search. Depth and count are capped so the
        triage stays fast and doesn't look like a mass file crawl.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Roots,
        [Parameter(Mandatory)][string[]]$NamePatterns,
        [int]$Depth = 4,
        [int]$MaxResults = 500
    )
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Roots) {
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        $items = Get-ChildItem -LiteralPath $r -Recurse -Depth $Depth -Force -ErrorAction SilentlyContinue
        foreach ($i in $items) {
            if (Test-PatternMatch -Text $i.Name -Patterns $NamePatterns) {
                $found.Add([pscustomobject]@{
                    Path = $i.FullName; IsFolder = $i.PSIsContainer
                    Size = if ($i.PSIsContainer) { $null } else { $i.Length }
                    Created = $i.CreationTime; Modified = $i.LastWriteTime
                })
                if ($found.Count -ge $MaxResults) { return $found }
            }
        }
    }
    return $found
}

function Get-ScreenConnectFolders {
    $roots = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemRoot\Temp") | Where-Object { $_ }
    # The 32-bit client service runs as SYSTEM, so its profile data lands under SysWOW64\config\systemprofile
    $profiles = @("$env:SystemRoot\System32\config\systemprofile", "$env:SystemRoot\SysWOW64\config\systemprofile") +
                @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    foreach ($p in $profiles) {
        $roots += Join-Path $p 'AppData\Local'
        $roots += Join-Path $p 'AppData\Roaming'
        $roots += Join-Path $p 'AppData\Local\Temp'      # extracted client copies (Temp\ScreenConnect\<version>)
        $roots += Join-Path $p 'AppData\Local\Apps\2.0'  # ClickOnce-deployed clients
    }
    foreach ($r in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -LiteralPath $r -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^ScreenConnect' } |
            Select-Object -ExpandProperty FullName
    }
}

function Get-FileHashSafe {
    param([string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $null }
}

function Get-SignatureSummary {
    param([string]$Path)
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        [pscustomobject]@{ Status = [string]$s.Status; Signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null } }
    } catch { [pscustomobject]@{ Status = 'Error'; Signer = $null } }
}

# ---------------------------------------------------------------------------
# ScreenConnect verification (pure: takes a state object, used by cleanup + tests)
# ---------------------------------------------------------------------------

function Write-VerificationReport {
    param($state, [string]$heading, $survivors = @())
    # Items owned by intentionally-kept instances ($survivors) are logged as KEPT and don't fail the check.
    # Shared items (ProgramData\ScreenConnect, System32 DLLs, LSA token) are kept whenever any survivor exists.
    $ids  = @($survivors | ForEach-Object { $_.ClientId } | Where-Object { $_ })
    $dirs = @($survivors | ForEach-Object { $_.InstallFolder } | Where-Object { $_ })
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($label, $text, $shared) $items.Add([pscustomobject]@{ Label = $label; Text = [string]$text; Shared = [bool]$shared }) }
    foreach ($x in $state.Instances)     { & $add "Service: $($x.ServiceName)" "$($x.ServiceName) ($($x.ClientId))" $false }
    foreach ($x in $state.OtherServices) { & $add "Service: $($x.Name)" $x.Name $false }
    foreach ($x in $state.Processes)     { & $add "Process: $($x.Name) PID $($x.ProcessId)" $x.ExecutablePath $false }
    foreach ($x in $state.Uninstall)     { & $add "Installed entry: $($x.DisplayName)$(if ($x.SystemComponent) { ' (hidden)' })" $x.DisplayName $false }
    foreach ($x in $state.Msi)           { & $add "MSI registration: $($x.ProductName) $($x.ProductCode)" $x.ProductName $false }
    foreach ($x in $state.Tasks)         { & $add "Scheduled task: $($x.TaskPath)$($x.TaskName)" "$($x.TaskName) $($x.Actions)" $false }
    foreach ($x in $state.RunKeys)       { & $add "Run key: $($x.Location)\$($x.Name)" "$($x.Name) $($x.Command)" $false }
    foreach ($x in $state.Startup)       { & $add "Startup item: $($x.Location)\$($x.Name)" "$($x.Name) $($x.Target)" $false }
    foreach ($x in $state.Folders)       { & $add "Folder: $x" $x ($x -notmatch 'ScreenConnect Client \(') }
    foreach ($x in $state.SystemDlls)    { & $add "System DLL: $x" $x $true }
    foreach ($x in $state.LsaScreenConnect) { & $add "LSA package entry: $x" $x $true }

    $remaining = New-Object System.Collections.Generic.List[string]
    Write-TriageLog "--- $heading ---"
    foreach ($i in $items) {
        $kept = $survivors -and ($i.Shared -or ($ids -and (Test-InScope $i.Text $ids)) -or @($dirs | Where-Object { $i.Text -like "$_*" }).Count)
        if ($kept) { Write-TriageLog "KEPT (instance not targeted): $($i.Label)" } else { $remaining.Add($i.Label) }
    }
    if ($remaining.Count -eq 0) { Write-TriageLog 'PASS: no targeted ScreenConnect services, processes, install entries, tasks, startup items, folders or LSA entries remain.' -Level OK }
    else { foreach ($r in $remaining) { Write-TriageLog "REMAINING: $r" -Level WARN } }
    return ,$remaining
}

# ---------------------------------------------------------------------------
# result.json: the contract between the scripts and Toolkit-GUI.ps1
# ---------------------------------------------------------------------------

function Write-ToolkitResult {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][ValidateSet('Triage','Cleanup','Verify')][string]$Tool,
        [int]$ExitCode,
        [Parameter(Mandatory)][ValidateSet('Red','Amber','Green')][string]$Verdict,
        [bool]$DryRun = $false,
        $Instances = @(),
        [string[]]$TrustedHosts = @(),
        $Connections = @(),
        $Findings = @(),
        [string]$NextStep = '',
        [ValidateSet('','Triage','DryRun','Cleanup','Verify')][string]$NextAction = '',
        [string]$SummaryPath = ''
    )
    $r = [pscustomobject][ordered]@{
        Tool        = $Tool
        Computer    = $env:COMPUTERNAME
        Time        = (Get-Date).ToString('o')
        ExitCode    = $ExitCode
        Verdict     = $Verdict
        DryRun      = $DryRun
        Instances   = @($Instances | ForEach-Object { [pscustomobject][ordered]@{
                          ClientId = $_.ClientId; CallbackHost = $_.CallbackHost; CallbackPort = $_.CallbackPort
                          SessionType = $_.SessionType; Trusted = [bool](Test-HostListed $_.CallbackHost $TrustedHosts -Trusted) } })
        Connections = @($Connections | ForEach-Object { [pscustomobject][ordered]@{
                          ProcessId = $_.OwningProcess; Remote = "$($_.RemoteAddress):$($_.RemotePort)"; State = [string]$_.State } })
        Findings    = @($Findings | ForEach-Object { [pscustomobject][ordered]@{ Severity = $_.Severity; Category = $_.Category; Title = $_.Title } })
        NextStep    = $NextStep
        NextAction  = $NextAction
        SummaryPath = $SummaryPath
    }
    $r | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $Folder 'result.json') -Encoding UTF8
}

function Get-ToolkitGate {
    # Guided order: triage -> dry run -> (offline) cleanup. Results = parsed result.json objects for this PC.
    param($Results = @(), [string[]]$OnlineAdapters = @(), [bool]$Disconnected)
    $triage = $Results | Where-Object { $_.Tool -eq 'Triage' } | Sort-Object { [datetime]$_.Time } -Descending | Select-Object -First 1
    $dry = if ($triage) { $Results | Where-Object { $_.Tool -eq 'Cleanup' -and $_.DryRun -and [datetime]$_.Time -gt [datetime]$triage.Time } | Select-Object -First 1 }
    $why = New-Object System.Collections.Generic.List[string]
    if (-not $triage) { $why.Add('run Triage first') }
    elseif (-not $dry) { $why.Add('run Cleanup dry run first') }
    if (-not $Disconnected) { $why.Add("tick 'I have disconnected the network'") }
    if ($OnlineAdapters) { $why.Add("still online via: $($OnlineAdapters -join ', ')") }
    [pscustomobject]@{
        Triage      = $triage
        DryRunOpen  = [bool]$triage
        CleanupOpen = $why.Count -eq 0
        Reason      = $why -join '; '
    }
}

Export-ModuleMember -Function *
