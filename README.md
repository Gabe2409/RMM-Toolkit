# RMM Incident Toolkit

Technician toolkit for Windows machines compromised by phishing campaigns that drop
remote-access software — currently focused on preconfigured **ScreenConnect "Access"**
clients (fake invitation → ClickFix/fake CAPTCHA → installer → unattended access →
possible HideUL concealment).

Scan-first, read-only by default. Removal is a separate, narrowly scoped script.

```
RMM-Toolkit\
├── Launch.bat                  START HERE. Double-click: asks for admin once, opens the window.
├── Toolkit-GUI.ps1             The guided window (runs the scripts below, shows result.json).
├── RMM-Triage.ps1              READ-ONLY. Detection, IOC extraction, reports. Exit 0/1/2.
├── ScreenConnect-Cleanup.ps1   ScreenConnect removal only. Dry run, evidence, verify.
├── Get-InstalledPrograms.ps1   Registry-based installed-program inventory.
├── lib\RMMToolkit.Common.psm1  Shared read-only helpers (no state changes in here).
├── config\rmm-signatures.json  RMM vendor signatures — add vendors here, no code changes.
├── config\ioc-watchlist.json   HideUL names, lure keywords, suspicious command patterns,
│                               known-bad hosts, your trusted RMM hosts.
└── tests\Run-Tests.ps1         Parser/IOC unit tests (no Pester needed).
```

## Field workflow

Plug in the USB stick and double-click **`Launch.bat`**. Accept the UAC prompt. Then follow the window top to bottom:

1. **Run Triage.** Changes nothing. The result panel shows a colored verdict, the next step, every
   ScreenConnect client (client ID, callback host/port; **Copy** puts them on the clipboard) and any
   **LIVE** remote-access connection.
2. **Cleanup dry run.** Unlocks after a triage. Untick any client you want to keep (your own MSP's
   trusted clients start unticked). Shows what would be removed; changes nothing.
3. **Disconnect the network** (cable out, Wi-Fi off) and tick the box. **Cleanup** stays locked until
   triage and a dry run exist *and* no network adapter has a default gateway; the window names the one
   still online (VPN adapters such as ZeroTier count).
4. **Cleanup** asks once to confirm, then runs every step without further prompts.
5. **Reboot while still offline**, run Launch.bat again, click **Verify**, then Triage once more.

The **Do it** button runs whatever the result suggests next. The window reads its state from the output
folder, so closing and reopening it (or rebooting) keeps your place. Each script runs in its own console
window so you can watch progress.

### Manual fallback (no window)

Open **PowerShell as Administrator** and `cd` into the folder.

```powershell
# 1. Triage (changes nothing). Add -IncludeBrowser for downloads/extensions/notifications.
powershell -ExecutionPolicy Bypass -File .\RMM-Triage.ps1 -IncludeBrowser

# 2. Read C:\Users\Public\RMM-Triage\<PC>_triage_<time>\incident-summary.txt
#    Note the client ID, callback host/port, session ID.

# 3. Disconnect the network (unplug / Wi-Fi off).

# 4. Dry run, then the real thing
.\ScreenConnect-Cleanup.ps1 -WhatIf
.\ScreenConnect-Cleanup.ps1                        # prompts per step: y / n / a(ll)
#   multiple instances?  .\ScreenConnect-Cleanup.ps1 -ClientId 1a2b3c4d5e6f7a8b

# 5. Reboot while still offline, then verify
.\ScreenConnect-Cleanup.ps1 -VerifyOnly
.\RMM-Triage.ps1                                   # full rescan
```

`-ExecutionPolicy Bypass` on the command line only affects that one process; it doesn't
change machine policy. It is the only policy accommodation the toolkit makes. `Launch.bat` does the
same, and also runs `Unblock-File` on the toolkit folder (files from a downloaded zip). A Group Policy
execution policy overrides `Bypass`; on such machines the scripts won't start.

## What the cleanup does, in order

| Step | Action | Safety |
|---|---|---|
| 0 | Discover instances | Refuses if >1 instance and no `-ClientId`/`-AllInstances`. Skips hosts in `trustedTenantHosts`. |
| 1 | Evidence | IOC CSV, `reg export` of service/uninstall/LSA keys, SHA256 + signature of every file, config/log copies, ScreenConnect event-log entries, zip of install folders. |
| 2 | Contain | Service set to **Disabled** then stopped (so recovery actions can't respawn it), then leftover `ScreenConnect.*` processes ended. |
| 3 | Uninstall | `msiexec /x {code} /qn /norestart` with verbose log. Product code from the Uninstall key, or from `Installer\Products` if the entry was hidden. Never executes arbitrary uninstall strings. |
| 4 | Orphaned services | `sc delete` for any `ScreenConnect*` service still in scope. |
| 5 | Remnants | Scheduled tasks (XML exported first), Run values, Startup shortcuts. |
| 6 | LSA | Prints all three LSA package lists. A leftover ScreenConnect entry is **reported only** unless you pass `-RemoveLsaEntry`, which removes just that token, requires `msv1_0` to remain, and is backed up in step 1. |
| 7 | Folders | Only folders named `ScreenConnect*` under Program Files, ProgramData, systemprofile or C:\Users. System32 ScreenConnect DLLs are kept while still LSA-registered. |
| 8 | Verify | Full rescan; PASS/ITEMS REMAIN in `cleanup-summary.txt`. |

## Output (`C:\Users\Public\RMM-Triage\<PC>_<mode>_<timestamp>\`)

- `incident-summary.txt` — the technician summary (computer, user, IOCs, services, other RMM, persistence, actions, verification, follow-up)
- `customer-summary.txt` — plain-language version for the customer
- `findings.csv`, `installed-programs.csv`, `timeline.csv` (MSI installs + new services), `browser.csv`
- `technician-log.txt` — timestamped log of everything
- `raw\*.json` — full structured data
- cleanup runs add `actions.csv`, `cleanup-summary.txt`, `evidence\`
- `result.json`: a short result the window reads (verdict, instances, live connections, top findings,
  next step). Every triage, cleanup and verify run writes one.

## Extending

- **New RMM vendor:** add a block to `config\rmm-signatures.json`.
- **Your own MSP's ScreenConnect:** put its relay hostname in `trustedTenantHosts` so it reports as Info and cleanup skips it. Exact hostname or a wildcard such as `*.mymsp.com` — not regex, so lookalike hosts can't pass as trusted.
- **Confirmed attacker host:** add to `knownBadHosts` — always reported High.
- **New lure wording / hiding tool:** `lureFileNames`, `hidingToolFiles`.
- **New check:** add a read-only function to the module, call it from `RMM-Triage.ps1`, emit `New-Finding`.

## Working with endpoint protection

The split is deliberate: the triage script only reads, and the cleanup script only touches
ScreenConnect. If AV still flags something:

1. Sign the scripts with a code-signing certificate (`Set-AuthenticodeSignature`) — the biggest single improvement.
2. Run from a consistent path and submit the files to the vendor as false positives.
3. If a specific check trips a behavioural rule, narrow or split that check. Don't obfuscate or add evasion.

## Roadmap

- `RMM-Cleanup.ps1` — technician-selected removal for other vendors (per-vendor, explicit `-Vendor`, never automatic)
- HideUL artifact removal step after evidence capture
- HTML customer report
- Firefox profile support; browser history check for lure domains
- Event-log parsing of ScreenConnect session start/end for an attacker-activity timeline
