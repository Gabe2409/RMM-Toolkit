#Requires -Version 5.1
<#
.SYNOPSIS
    Guided window for the toolkit. Start it with Launch.bat (elevates, process-scope policy).

.DESCRIPTION
    No detection logic here: the window only builds arguments, runs the
    scripts in their own console, and shows the result.json they write.
    Guided order: Triage -> Cleanup dry run -> disconnect -> Cleanup -> reboot -> Verify.
    Gate state is read from the output folder, so it survives closing the window.
#>
param([string]$OutputRoot = 'C:\Users\Public\RMM-Triage')

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Import-Module (Join-Path $PSScriptRoot 'lib\RMMToolkit.Common.psm1') -Force -DisableNameChecking
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:proc = $null; $script:runTool = ''; $script:runStart = $null
$script:results = @(); $script:gate = $null; $script:shown = $null; $script:instTime = ''; $script:tick = 0
$exitText = @{ 10 = 'not running as Administrator'; 11 = 'more than one instance - tick the ones to remove'; 12 = 'nothing in scope while other instances exist'; 13 = 'a config file in config\ is broken' }
$verdictColor = @{ Red = 'Firebrick'; Amber = 'DarkOrange'; Green = 'ForestGreen' }
$verdictWord = @{ Red = 'ACTION NEEDED'; Amber = 'REVIEW'; Green = 'OK' }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function New-Ctl([string]$Type, $Parent, [int]$X, [int]$Y, [int]$W, [int]$H, [string]$Text = '', [string]$Anchor = 'Top,Left') {
    $c = New-Object "System.Windows.Forms.$Type"
    $c.SetBounds($X, $Y, $W, $H); $c.Text = $Text; $c.Anchor = $Anchor
    $Parent.Controls.Add($c); $c
}
function Set-Click($Button, [scriptblock]$Action) {
    # Errors inside WinForms handlers would vanish into the hidden console; show them in the log instead
    $Button.Tag = $Action
    $Button.Add_Click({ param($s) try { & $s.Tag } catch { Write-Log "ERROR: $($_.Exception.Message)" } })
}
function Write-Log([string]$Text) { $txtLog.AppendText("$(Get-Date -Format 'HH:mm:ss')  $Text`r`n") }
function Show-Message([string]$Text, [string]$Buttons = 'OK') { [System.Windows.Forms.MessageBox]::Show($form, $Text, 'RMM Toolkit', $Buttons) }

function Get-Results {
    Get-ChildItem -LiteralPath $OutputRoot -Filter result.json -Recurse -Depth 1 -ErrorAction SilentlyContinue |
        ForEach-Object { try { Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json } catch { } } |
        Where-Object { $_.Computer -eq $env:COMPUTERNAME }
}
function Get-OnlineAdapters {
    # Online = an Up adapter that holds a default route
    $idx = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex -Unique)
    if (-not $idx) { return @() }
    @(Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name)
}

function Start-Tool([string]$Tool, [string]$Script, [string[]]$ToolArgs) {
    if ($script:proc) { return }
    $file = Join-Path $PSScriptRoot $Script
    $line = "-NoProfile -ExecutionPolicy Bypass -File `"$file`" -OutputRoot `"$OutputRoot`" $($ToolArgs -join ' ')"
    Write-Log "Running $Script $($ToolArgs -join ' ')   (progress in the console window)"
    $script:runTool = $Tool; $script:runStart = Get-Date
    $script:proc = Start-Process powershell.exe -ArgumentList $line -PassThru
    [void]$script:proc.Handle   # keep the handle so ExitCode is readable after exit (PS 5.1)
    $lblStatus.Text = "Running $Tool ..."
    Update-Gate
}

function Get-CleanupArgs {
    # Instances come from the last triage; trusted (own MSP) ones start unticked
    $checked = @($lvInst.CheckedItems | ForEach-Object { $_.Tag })
    if ($lvInst.Items.Count -and -not $checked) { [void](Show-Message 'Tick at least one ScreenConnect instance to remove.'); return $null }
    $a = @()
    $ids = @($checked | ForEach-Object { $_.ClientId } | Where-Object { $_ -match '^[0-9a-fA-F]+$' })
    if ($ids) { $a += "-ClientId $($ids -join ',')" }
    if ($checked | Where-Object { $_.Trusted }) { $a += '-IncludeTrusted' }
    if ($chkLsa.Checked) { $a += '-RemoveLsaEntry' }
    return ,$a
}

function Show-Result($r) {
    $script:shown = $r
    $when = ([datetime]$r.Time).ToString('yyyy-MM-dd HH:mm')
    $lblVerdict.Text = "  $($verdictWord[$r.Verdict]) - $($r.Tool)$(if ($r.DryRun) { ' (dry run, nothing changed)' })   $when"
    $lblVerdict.BackColor = [System.Drawing.Color]::FromName($verdictColor[$r.Verdict])
    $lblNext.Text = "Next step: $($r.NextStep)"
    $btnNext.Enabled = [bool]$r.NextAction
    $btnNext.Text = if ($r.NextAction) { "Do it: $($r.NextAction)" } else { 'Next step' }
    $lvFind.Items.Clear()
    foreach ($c in @($r.Connections)) {
        $it = $lvFind.Items.Add($(if ($c.State -eq 'Established') { 'LIVE' } else { 'Conn' }))
        [void]$it.SubItems.Add('Connection'); [void]$it.SubItems.Add("PID $($c.ProcessId) -> $($c.Remote) [$($c.State)]")
        if ($c.State -eq 'Established') { $it.ForeColor = [System.Drawing.Color]::Firebrick }
    }
    foreach ($f in @($r.Findings)) {
        $it = $lvFind.Items.Add([string]$f.Severity)
        [void]$it.SubItems.Add([string]$f.Category); [void]$it.SubItems.Add([string]$f.Title)
        if ($f.Severity -eq 'High') { $it.ForeColor = [System.Drawing.Color]::Firebrick }
    }
    if (-not $lvFind.Items.Count) { $it = $lvFind.Items.Add(''); [void]$it.SubItems.Add(''); [void]$it.SubItems.Add('No High or Medium findings.') }
}

function Update-Gate {
    $online = @(Get-OnlineAdapters)
    $g = Get-ToolkitGate -Results $script:results -OnlineAdapters $online -Disconnected $chkOffline.Checked
    $script:gate = $g
    if ($g.Triage -and $g.Triage.Time -ne $script:instTime) {
        $script:instTime = $g.Triage.Time
        $lvInst.Items.Clear()
        foreach ($i in @($g.Triage.Instances)) {
            $it = $lvInst.Items.Add([string]$i.ClientId)
            foreach ($v in $i.CallbackHost, $i.CallbackPort, $i.SessionType, $(if ($i.Trusted) { 'yes (your MSP)' } else { 'NO' })) { [void]$it.SubItems.Add([string]$v) }
            $it.Tag = $i; $it.Checked = -not $i.Trusted
        }
        $lblInst.Text = if ($lvInst.Items.Count) { 'ScreenConnect clients from the last triage (ticked = will be removed):' } else { 'Last triage found no ScreenConnect client service. Cleanup removes leftovers only.' }
    }
    $busy = [bool]$script:proc
    $btnTriage.Enabled = -not $busy
    $btnVerify.Enabled = -not $busy
    $btnDry.Enabled = -not $busy -and $g.DryRunOpen
    $btnClean.Enabled = -not $busy -and $g.CleanupOpen
    $lblGate.Text = if ($g.CleanupOpen) { 'Cleanup unlocked.' } else { "Cleanup locked: $($g.Reason)." }
    $lblGate.ForeColor = if ($g.CleanupOpen) { [System.Drawing.Color]::ForestGreen } else { [System.Drawing.Color]::Firebrick }
    if (-not $busy) { $lblStatus.Text = 'Ready.' }
}

# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "RMM Toolkit - $env:COMPUTERNAME$(if (-not (Test-IsAdmin)) { '   [NOT ADMIN - start with Launch.bat]' })"
$form.Size = New-Object System.Drawing.Size(1000, 760)
$form.MinimumSize = New-Object System.Drawing.Size(900, 640)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$grpScan = New-Ctl GroupBox $form 10 8 260 262 '1. Scan (changes nothing)'
$btnTriage = New-Ctl Button $grpScan 12 24 234 40 'Run Triage'
$chkBrowser = New-Ctl CheckBox $grpScan 12 74 234 22 'Include browser (downloads, extensions)'
$chkSweep = New-Ctl CheckBox $grpScan 12 98 234 22 'Skip file sweep (faster)'
[void](New-Ctl Label $grpScan 12 126 120 20 'Look back (days):')
$numDays = New-Ctl NumericUpDown $grpScan 136 124 60 22
$numDays.Minimum = 1; $numDays.Maximum = 365; $numDays.Value = 14
$btnVerify = New-Ctl Button $grpScan 12 168 234 34 'Verify (after reboot)'
[void](New-Ctl Label $grpScan 12 206 234 46 'Verify checks that no targeted ScreenConnect remains. Always available.')

$grpClean = New-Ctl GroupBox $form 280 8 694 262 '2. Remove ScreenConnect' 'Top,Left,Right'
$lblInst = New-Ctl Label $grpClean 12 20 670 18 'Run Triage first.' 'Top,Left,Right'
$lvInst = New-Ctl ListView $grpClean 12 40 580 100 '' 'Top,Left,Right'
$lvInst.View = 'Details'; $lvInst.CheckBoxes = $true; $lvInst.FullRowSelect = $true
foreach ($c in @(@('Client ID', 140), @('Callback host', 230), @('Port', 50), @('Type', 70), @('Trusted', 90))) { [void]$lvInst.Columns.Add($c[0], $c[1]) }
$btnCopyInst = New-Ctl Button $grpClean 600 40 82 30 'Copy' 'Top,Right'
$chkLsa = New-Ctl CheckBox $grpClean 12 146 670 22 'Also remove a leftover ScreenConnect LSA entry (backed up first; only if the summary says it is still there)'
$chkOffline = New-Ctl CheckBox $grpClean 12 170 670 22 'I have disconnected the network (cable out, Wi-Fi off)'
$lblGate = New-Ctl Label $grpClean 12 194 670 20 '' 'Top,Left,Right'
$btnDry = New-Ctl Button $grpClean 12 216 200 36 'Cleanup dry run'
$btnClean = New-Ctl Button $grpClean 222 216 200 36 'Cleanup (removes)'

$grpRes = New-Ctl GroupBox $form 10 276 964 316 'Result' 'Top,Bottom,Left,Right'
$lblVerdict = New-Ctl Label $grpRes 12 22 940 40 '  No result yet.' 'Top,Left,Right'
$lblVerdict.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
$lblVerdict.ForeColor = [System.Drawing.Color]::White; $lblVerdict.BackColor = [System.Drawing.Color]::Gray; $lblVerdict.TextAlign = 'MiddleLeft'
$lblNext = New-Ctl Label $grpRes 12 68 760 36 '' 'Top,Left,Right'
$lblNext.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnNext = New-Ctl Button $grpRes 782 66 170 34 'Next step' 'Top,Right'
$btnNext.Enabled = $false
$lvFind = New-Ctl ListView $grpRes 12 108 940 166 '' 'Top,Bottom,Left,Right'
$lvFind.View = 'Details'; $lvFind.FullRowSelect = $true
foreach ($c in @(@('Severity', 70), @('Category', 110), @('Finding', 740))) { [void]$lvFind.Columns.Add($c[0], $c[1]) }
$btnCopyFind = New-Ctl Button $grpRes 12 280 120 28 'Copy selected' 'Bottom,Left'
$btnSummary = New-Ctl Button $grpRes 140 280 140 28 'Open full summary' 'Bottom,Left'
$btnFolder = New-Ctl Button $grpRes 288 280 140 28 'Open output folder' 'Bottom,Left'
$lblStatus = New-Ctl Label $grpRes 440 284 512 20 'Ready.' 'Bottom,Left,Right'

$txtLog = New-Ctl TextBox $form 10 598 964 112 '' 'Bottom,Left,Right'
$txtLog.Multiline = $true; $txtLog.ReadOnly = $true; $txtLog.ScrollBars = 'Vertical'; $txtLog.BackColor = [System.Drawing.Color]::White

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
Set-Click $btnTriage {
    $a = @("-RecentDays $([int]$numDays.Value)")
    if ($chkBrowser.Checked) { $a += '-IncludeBrowser' }
    if ($chkSweep.Checked) { $a += '-SkipFileSweep' }
    Start-Tool 'Triage' 'RMM-Triage.ps1' $a
}
Set-Click $btnDry {
    $a = Get-CleanupArgs
    if ($null -ne $a) { Start-Tool 'Cleanup' 'ScreenConnect-Cleanup.ps1' (@($a) + '-WhatIf') }
}
Set-Click $btnClean {
    $a = Get-CleanupArgs
    if ($null -eq $a) { return }
    $what = if ($lvInst.Items.Count) { ($lvInst.CheckedItems | ForEach-Object { "  $($_.Text) -> $($_.SubItems[1].Text)" }) -join "`r`n" } else { '  all ScreenConnect leftovers' }
    $warn = if ($a -contains '-IncludeTrusted') { "`r`n`r`nWARNING: this includes an instance on YOUR trusted list." } else { '' }
    if ((Show-Message "Remove these ScreenConnect clients?`r`n`r`n$what$warn`r`n`r`nEvidence is saved first. This cannot be undone." 'YesNo') -ne 'Yes') { return }
    Start-Tool 'Cleanup' 'ScreenConnect-Cleanup.ps1' (@($a) + '-Force')
}
Set-Click $btnVerify { Start-Tool 'Verify' 'ScreenConnect-Cleanup.ps1' @('-VerifyOnly') }
Set-Click $btnNext {
    $b = @{ Triage = $btnTriage; DryRun = $btnDry; Cleanup = $btnClean; Verify = $btnVerify }[[string]$script:shown.NextAction]
    if (-not $b) { return }
    if ($b.Enabled) { $b.PerformClick() }
    elseif ($script:proc) { [void](Show-Message 'A script is still running.') }
    else { [void](Show-Message "Not yet: $($script:gate.Reason).$(if ($script:shown.NextAction -eq 'Verify') { "`r`nReboot first if you just ran Cleanup." })") }
}
Set-Click $btnCopyInst {
    $rows = if ($lvInst.SelectedItems.Count) { @($lvInst.SelectedItems) } else { @($lvInst.CheckedItems) }
    if ($rows) { [System.Windows.Forms.Clipboard]::SetText((($rows | ForEach-Object { "Client ID $($_.Text)  host $($_.SubItems[1].Text):$($_.SubItems[2].Text)  type $($_.SubItems[3].Text)" }) -join "`r`n")) ; Write-Log 'Copied instance IOCs.' }
}
Set-Click $btnCopyFind {
    $rows = @($lvFind.SelectedItems)
    if ($rows) { [System.Windows.Forms.Clipboard]::SetText((($rows | ForEach-Object { "[$($_.Text)] $($_.SubItems[1].Text): $($_.SubItems[2].Text)" }) -join "`r`n")); Write-Log "Copied $($rows.Count) row(s)." }
}
Set-Click $btnSummary {
    if ($script:shown -and $script:shown.SummaryPath -and (Test-Path -LiteralPath $script:shown.SummaryPath)) { Start-Process notepad.exe -ArgumentList "`"$($script:shown.SummaryPath)`"" }
    else { [void](Show-Message 'No summary for this result.') }
}
Set-Click $btnFolder {
    $dir = if ($script:shown -and $script:shown.SummaryPath) { Split-Path -Parent $script:shown.SummaryPath } else { $OutputRoot }
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Start-Process explorer.exe -ArgumentList "`"$dir`""
}
$chkOffline.Add_CheckedChanged({ Update-Gate })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    try {
        $script:tick++
        if ($script:proc -and $script:proc.HasExited) {
            $code = $script:proc.ExitCode
            $script:proc = $null
            $script:results = @(Get-Results)
            $r = $script:results | Where-Object { $_.Tool -eq $script:runTool -and [datetime]$_.Time -ge $script:runStart.AddSeconds(-2) } |
                Sort-Object { [datetime]$_.Time } -Descending | Select-Object -First 1
            if ($r) { Show-Result $r; Write-Log "$script:runTool finished: $($r.Verdict) (exit $code)" }
            else { Write-Log "$script:runTool stopped without a result (exit $code$(if ($exitText.ContainsKey($code)) { ": $($exitText[$code])" })). See technician-log.txt in the output folder." }
            Update-Gate
        } elseif (-not $script:proc -and $script:tick % 5 -eq 0) { Update-Gate }   # re-check the network every 5 s
    } catch { Write-Log "ERROR: $($_.Exception.Message)" }
})
$form.Add_FormClosing({
    param($s, $e)
    if ($script:proc -and -not $script:proc.HasExited -and (Show-Message 'A script is still running in its console. Close this window anyway?' 'YesNo') -ne 'Yes') { $e.Cancel = $true }
})
$form.Add_Shown({
    $script:results = @(Get-Results)
    $last = $script:results | Sort-Object { [datetime]$_.Time } -Descending | Select-Object -First 1
    if ($last) { Show-Result $last; Write-Log "Loaded last result: $($last.Tool) at $($last.Time)" }
    Update-Gate
    if (-not (Test-IsAdmin)) { Write-Log 'Not elevated: Cleanup will refuse to run. Close and start Launch.bat.' }
    $timer.Start()
})

[void]$form.ShowDialog()
$timer.Stop()
