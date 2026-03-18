# T1562.001-32: Disable or Modify Tools — LockBit Black - Disable Privacy Settings Experience Using Registry (cmd)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes registry
modifications that suppress or disable Windows security and privacy components. This test
replicates a technique attributed to LockBit Black, which uses `reg.exe` to set
`DisablePrivacyExperience` in the HKCU policy hive. The Privacy Settings Experience is the
Windows Out-of-Box Experience (OOBE) privacy consent dialog. Suppressing it prevents users
from reviewing privacy configurations that control diagnostic data collection, telemetry, and
other settings. Ransomware operators use this as pre-encryption housekeeping to remove
post-reboot first-run experiences that could alert a user or generate additional telemetry.

This is the `cmd.exe` variant. The parallel PowerShell-native variant is test 34. Comparing
the two datasets shows how the same registry modification leaves different telemetry footprints
depending on execution vector.

In this **undefended** dataset, Defender is disabled. The registry modification succeeds.

## What This Dataset Contains

The dataset captures 102 events across two channels (96 PowerShell, 6 Security) spanning
approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Full process chain from PowerShell to cmd.exe to reg.exe.** Six
process creation events capture the complete execution:

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. `"cmd.exe" /c reg add "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f`
3. `reg  add "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f` (reg.exe child of cmd.exe)
4. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)
5. `"cmd.exe" /c reg delete "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /f >nul 2>&1` (cleanup)
6. `reg  delete "HKCU\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /f` (cleanup reg.exe child)

Events 5 and 6 are the ART cleanup phase restoring the original state. The double-space in
`reg  add` and `reg  delete` is a characteristic artifact of how `cmd.exe` passes arguments
when invoked via `/c`.

The parent process for `cmd.exe` is `C:\Windows\System32\WindowsPowerShell\v1.0\
powershell.exe` running as `NT AUTHORITY\SYSTEM` (Logon ID `0x3E7`,
`MandatoryLabel: S-1-16-16384`).

**PowerShell EID 4104 — 95 script block events.** The substantive block is the cleanup
invocation:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 32 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

The ART test framework boilerplate (`Set-ExecutionPolicy Bypass`, `$ErrorActionPreference =
'Continue'`) is present. The `reg add` and `reg delete` commands execute via `cmd.exe` and
do not appear as 4104 script blocks.

**PowerShell EID 4103 — One module pipeline event** for the `Set-ExecutionPolicy` call.

**No EID 4100 error events.** The `reg.exe` operations completed successfully — no exceptions
were raised at the PowerShell test framework level.

## What This Dataset Does Not Contain

**No Sysmon events.** The bundled channels are PowerShell/Operational and Security only.
The defended dataset includes Sysmon EID 1 (process creates for the full `powershell.exe`
→ `cmd.exe` → `reg.exe` chain), EID 7 (image loads), and EID 10 (process access events).
None of that appears here.

**No Sysmon EID 13 (registry value set).** The HKCU OOBE policy path
(`HKCU\Software\Policies\Microsoft\Windows\OOBE`) is not covered by the sysmon-modular
EID 13 include rules — this was also absent in the defended variant. The `reg.exe` 4688
command line with the full key path and value is the primary registry modification artifact.

**No Security 4657 (registry object modification).** Object access auditing for registry
keys is not configured for the HKCU policy hive in this environment. The modification is
only visible through the `reg.exe` command line in 4688.

**Cleanup events.** The dataset includes the ART cleanup `reg delete` (events 5 and 6).
These are test framework artifacts and would not appear in a real attack. They indicate the
value `DisablePrivacyExperience` was written and then removed by the test framework.

## Assessment

This dataset demonstrates a **successful** LockBit Black registry modification technique with
Defender disabled. The full `cmd.exe` → `reg.exe` execution chain is captured in Security
4688, including both the attack and cleanup phases. The key path
`HKCU\Software\Policies\Microsoft\Windows\OOBE`, value name `DisablePrivacyExperience`, type
`REG_DWORD`, data `1` are all visible in the command lines.

Compared to the defended variant (which also succeeded — this modification is not blocked by
Defender or Tamper Protection), the undefended dataset produces equivalent 4688 evidence.
The defended variant additionally includes Sysmon process tree data. The attack telemetry
itself is identical in both conditions for this technique.

Comparing this test to test 34 (PowerShell-native `New-ItemProperty` variant), the cmd.exe
variant produces more 4688 events (6 vs. 3) and provides the `cmd.exe` intermediate process
in the chain. The `reg.exe` double-space artifact in the command line also distinguishes
cmd.exe-based invocation from direct PowerShell registry API calls.

## Detection Opportunities Present in This Data

**Security EID 4688 — `reg.exe` or `cmd.exe` targeting
`HKCU\Software\Policies\Microsoft\Windows\OOBE` with `/v DisablePrivacyExperience`.** The
exact key, value name, and the use of `REG_DWORD /d 1` are directly readable from the
command line in both the `cmd.exe` and `reg.exe` 4688 events.

**Security EID 4688 — Double-space artifact in `reg.exe` command line.** The `reg  add`
pattern (two spaces between `reg` and `add`) is characteristic of commands passed through
`cmd.exe /c`. This artifact can be used to distinguish cmd.exe-sourced reg.exe invocations
from direct calls in detection queries.

**Security EID 4688 — PowerShell → cmd.exe → reg.exe chain with SYSTEM context.** The
three-hop process chain running as `NT AUTHORITY\SYSTEM` targeting an HKCU policy key is
not a normal administrative pattern. SYSTEM modifying `HKCU` policy is possible but unusual
and warrants investigation.

**Cleanup phase visibility.** The `reg delete` events (events 5 and 6) reveal that a value
was written and then removed. In a real attack, only the `reg add` would appear. Defenders
who see a `reg add` for `DisablePrivacyExperience` without a subsequent `reg delete` should
treat it as a higher-priority indicator.
