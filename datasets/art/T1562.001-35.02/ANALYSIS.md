# T1562.001-35: Disable or Modify Tools — LockBit Black - Use Registry Editor to Turn On Automatic Logon (PowerShell)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) covers registry
modifications that alter security-relevant system behavior. This test replicates the
LockBit Black autologon registry configuration technique using PowerShell's
`New-ItemProperty` cmdlet, directly paralleling the `cmd.exe` + `reg.exe` variant in
test 33. Automatic logon allows a system to boot directly to a user's desktop after a
forced reboot, enabling ransomware operators to resume payload execution without
requiring user interaction.

The PowerShell variant is functionally equivalent to test 33 but leaves a different
telemetry footprint: no `cmd.exe` or `reg.exe` child processes are created, and the full
configuration — including credential values — appears in the PowerShell script block in
addition to the 4688 command line.

In this **undefended** dataset, Defender is disabled. The registry writes succeed.

## What This Dataset Contains

The dataset captures 105 events across two channels (102 PowerShell, 3 Security) spanning
approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Three process creation events.** Unlike the cmd.exe variant (test 33,
which produces 7 events), this PowerShell-native approach produces only three:

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. The attack command in a single child PowerShell invocation:
   ```
   "powershell.exe" & {New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -PropertyType DWord -Value 1 -Force
   New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value Administrator -Force
   New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -Value contoso.com -Force
   New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword  -Value password1 -Force}
   ```
3. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)

All four registry values (`AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`,
`DefaultPassword`) with their credential values (`Administrator`, `contoso.com`,
`password1`) are directly readable in the single 4688 event for the child PowerShell.

The parent PowerShell runs as `NT AUTHORITY\SYSTEM`. No `cmd.exe` appears. No separate
`reg.exe` processes appear.

**PowerShell EID 4104 — 97 script block events.** The ART test framework boilerplate is present
(`Set-ExecutionPolicy Bypass`, `$ErrorActionPreference = 'Continue'`). The cleanup block:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 35 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

**PowerShell EID 4103 — Five module pipeline events** for the `Set-ExecutionPolicy` call
and associated pipeline activity.

**No EID 4100 error events.** All four `New-ItemProperty` calls completed without errors.

## What This Dataset Does Not Contain

**No `cmd.exe` or `reg.exe` process creation events.** The four registry values are written
using the PowerShell .NET registry API directly. This is the key distinguisher from test 33:
detections based solely on `reg.exe` command line monitoring, or on `cmd.exe` spawning
`reg.exe`, will not fire for this variant.

**No New-ItemProperty script blocks in 4104 capturing the credential values.** The child
PowerShell's script block logging captures the four `New-ItemProperty` calls — but those
blocks appear in the child process's `Microsoft-Windows-PowerShell/Operational` log, not
the parent's. The bundled dataset captures the parent's PowerShell log stream, not the
child's. The credential values appear in the 4688 command line but not in the sampled 4104
content.

**No Sysmon events.** Sysmon data is not bundled. The defended variant captures Sysmon EID 1
(process creates for `whoami.exe` and the child `powershell.exe`), EID 7 (image loads),
EID 10 (process access), and Security 4689 (exit statuses of `0x0` confirming success) and
notes ambient `WmiPrvSE.exe` activity.

**No Sysmon EID 13 (registry value set).** The Winlogon policy path
(`HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon`) is not included
in the sysmon-modular EID 13 rules — consistent with test 33.

## Assessment

This dataset documents a successful autologon credential write via PowerShell-native
`New-ItemProperty` calls on a host with Defender disabled. The telemetry is minimal compared
to test 33: three 4688 events versus seven, and the absence of any `cmd.exe` or `reg.exe`
in the process chain.

The most important forensic artifact is the single Security 4688 event for the child
`powershell.exe`, which contains all four credential values in the command line. This single
event contains more information than most of the seven events in test 33 combined, because
the entire `New-ItemProperty` block with all values appears in one command line string.

Comparing this dataset to test 33: the cmd.exe variant produces more events but each
individual `reg.exe` event contains only one value. The PowerShell variant produces fewer
events but concentrates all credential information in one 4688 event. Both leave a
`DefaultPassword` value written in plaintext in the registry, creating a credential
exposure risk that persists beyond the initial attack.

## Detection Opportunities Present in This Data

**Security EID 4688 — PowerShell command line containing `New-ItemProperty` targeting the
Winlogon policy key with `DefaultPassword`.** The presence of `DefaultPassword` in a
`New-ItemProperty` command targeting `HKLM:\Software\Policies\Microsoft\Windows NT\
CurrentVersion\Winlogon` is a highly specific autologon configuration indicator.

**Security EID 4688 — All four autologon values in a single PowerShell command line.** The
combination of `AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`, and
`DefaultPassword` in a single 4688 event is characteristic of ransomware-style autologon
configuration. Legitimate administrators rarely set all four in a single scripted operation.

**Behavioral comparison with test 33 (cmd.exe variant): absence of `reg.exe` as a signal.**
If your environment detects test 33 via `reg.exe` command line monitoring but not test 35,
you have a coverage gap. The PowerShell-native path bypasses any detection logic that
requires `reg.exe` to be spawned.

**Credential exposure in process creation logs.** The plaintext password value `password1`
(or a real attacker's chosen password) appearing in a Security 4688 event is a data
exposure issue beyond the attack detection itself. Process creation logging should be
treated as a sensitive log source precisely because it captures plaintext credential
arguments like these.
