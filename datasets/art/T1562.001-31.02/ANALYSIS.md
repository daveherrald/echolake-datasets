# T1562.001-31: Disable or Modify Tools — Tamper with Windows Defender ATP Using Aliases (PowerShell)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes modifying
security software configuration to reduce its effectiveness. Windows Defender exposes its
configuration through the `Set-MpPreference` PowerShell cmdlet. This technique uses
abbreviated parameter aliases to set four Defender configuration values that together
significantly weaken real-time protection:

- `-drtm` → `DisableRealtimeMonitoring`
- `-dbm` → `DisableBehaviorMonitoring`
- `-dscrptsc` → `DisableScriptScanning`
- `-dbaf` → `DisableBlockAtFirstSeen`

The alias approach can evade some detection rules that only look for the full parameter
names. This test runs all four `Set-MpPreference` calls in a single PowerShell block.

In this **undefended** dataset, Defender is disabled at the policy level. `Set-MpPreference`
is callable, and Tamper Protection is not engaged.

## What This Dataset Contains

The dataset captures 108 events across two channels (104 PowerShell, 3 Security) and one
additional Security event (Application EID 15) spanning approximately 5 seconds on
ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17T17:36).

**Security EID 4688 — The full Set-MpPreference command captured as the child PowerShell
command line:**

```
"powershell.exe" & {Set-MpPreference -drtm $True
Set-MpPreference -dbm $True
Set-MpPreference -dscrptsc $True
Set-MpPreference -dbaf $True}
```

The parent PowerShell (ART test framework) runs as `NT AUTHORITY\SYSTEM`. Two additional 4688
events capture `whoami.exe` pre- and post-execution checks.

**Application EID 15 — `SECURITY_PRODUCT_STATE_ON`.** The Defender Security Center
registration refreshed during the test window, consistent with `Set-MpPreference` triggering
a Defender configuration event even on a host with protection disabled.

**PowerShell EID 4103 — One module pipeline event** for `Set-ExecutionPolicy Bypass -Scope
Process` (ART test framework).

**PowerShell EID 4104 — 99 script block events.** The captured blocks are the ART test framework
boilerplate:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference = 'Continue'
```

And the cleanup block:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 31 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

The four `Set-MpPreference` calls do not appear as individual 4104 script blocks. They were
executed inside the child `powershell.exe` that was launched via `& {...}` from the parent
test framework, and the child's script block logging is captured in the 4688 command line rather
than appearing as separate 4104 events in the parent's log stream.

**No PowerShell EID 4100 error events.** `Set-MpPreference` returned silently without
errors. On a host with Defender disabled, the cmdlet accepts the preference values without
Tamper Protection rejection, and no exceptions are raised.

## What This Dataset Does Not Contain

**No registry write confirmation via Sysmon EID 13.** Sysmon is not bundled in this dataset.
Whether the `Set-MpPreference` calls actually modified registry keys under
`HKLM\SOFTWARE\Microsoft\Windows Defender\` cannot be confirmed from the available
telemetry. On a host with Defender disabled at the policy level, the preference writes may
or may not take effect depending on the specific policy mechanism.

**No Sysmon EID 1 for the child PowerShell.** Sysmon process create data is not present in
the bundled channels. The defended variant captures these via EID 1, including
`whoami.exe` and the child `powershell.exe` with the `Set-MpPreference` commands.

**No `Set-MpPreference` script block in 4104.** As noted above, the cmdlet executions occur
in the child PowerShell process whose 4104 stream is not captured in the bundled
`powershell.jsonl`. The 4688 command line is the sole log source capturing the abbreviated
aliases.

**No WMI or Defender state-change events.** The preferred confirmation that
`Set-MpPreference` actually committed the changes — Sysmon EID 13 for the Defender registry
key, or WMI events from the `MSFT_MpPreference` class — is absent.

## Assessment

The defining characteristic of this undefended dataset is the presence of the four
abbreviated `Set-MpPreference` alias invocations in a single Security 4688 command line
with no error events. In the defended dataset, `Set-MpPreference` also returned without
errors (Tamper Protection silently rejects the writes), making the defended and undefended
runs produce superficially similar telemetry at the PowerShell and Security event level.
The key difference is that on this host, the preference writes may actually take effect —
but no event in this dataset confirms that outcome.

The Application EID 15 `SECURITY_PRODUCT_STATE_ON` event is consistent with Defender's
Security Center handler being invoked by the `Set-MpPreference` call even when Defender
is disabled. This event appears in multiple tests in this series and is not a specific
indicator of the aliases technique.

## Detection Opportunities Present in This Data

**Security EID 4688 — `Set-MpPreference` with abbreviated aliases in the command line.**
The four aliases `-drtm`, `-dbm`, `-dscrptsc`, `-dbaf` as a group are a high-confidence
indicator. Defenders who have trained on full parameter names (`DisableRealtimeMonitoring`,
etc.) may miss this if their detection logic does not account for PowerShell cmdlet parameter
aliasing.

**Security EID 4688 — Multiple `Set-MpPreference` calls in a single PowerShell command
block.** Legitimate administrative use of `Set-MpPreference` rarely chains four preference
disablement calls in a single process invocation. The combination of `$True` values across
all four monitoring parameters together is an atypical legitimate pattern.

**Application EID 15 near suspicious PowerShell process creation.** The Security Center
state refresh fires within the same second as the `Set-MpPreference` execution and can
serve as a corroborating temporal marker.

**PowerShell EID 4104 in the child process context.** In environments where PowerShell
script block logging is configured to capture child process output, the individual
`Set-MpPreference -drtm $True` calls would appear as 4104 blocks in the child's log stream.
This dataset's collection did not capture the child's 4104 stream, but that channel is
available if your collection pipeline captures all PowerShell/Operational sources.
