# T1546.008-7: Accessibility Features — Replace Magnify.exe (Magnifier Binary) with cmd.exe

## Technique Context

T1546.008 (Accessibility Features) is exploitable through any of the Windows accessibility programs that run at the lock screen. `Magnify.exe` (Windows Magnifier) is one of the targets, invoked from the accessibility shortcut on the logon UI. Replacing it with a shell provides SYSTEM access before authentication, identical in impact to the `utilman.exe` variant. What makes this test notable from a telemetry perspective is the delivery mechanism: the test uses WMI (via `Win32_Process.Create`) rather than a direct PowerShell-to-cmd chain. This introduces `WmiPrvSE.exe` as the process parent, which is a well-known defense evasion and lateral movement pattern (T1047) in its own right.

## What This Dataset Contains

Sysmon EID 1 (ProcessCreate) shows five processes, and the first is significant:

```
Image: C:\Windows\System32\wbem\WmiPrvSE.exe
CommandLine: C:\Windows\system32\wbem\wmiprvse.exe -Embedding
RuleName: technique_id=T1047,technique_name=Windows Management Instrumentation
User: NT AUTHORITY\NETWORK SERVICE
```

`WmiPrvSE.exe` (running as NETWORK SERVICE) is the WMI provider host that spawns the attack chain. It is followed by:
- `whoami.exe` (SYSTEM context check, parent `powershell.exe`)
- `cmd.exe` with the full replacement command: `"cmd.exe" /c IF NOT EXIST C:\Windows\System32\Magnify_backup.exe (copy ...) & takeown /F C:\Windows\System32\Magnify.exe /A & icacls C:\Windows\System32\Magnify.exe /grant Administrators:F /t & copy C:\Windows\System32\cmd.exe C:\Windows\System32\Magnify.exe`
- `takeown.exe` (`/F C:\Windows\System32\Magnify.exe /A`, tagged `T1222.001`)
- `icacls.exe` (granting `Administrators:F` on `Magnify.exe`, tagged `T1222.001`)

Sysmon EID 11 captures the file overwrite: `C:\Windows\System32\Magnify.exe` written by `cmd.exe` as SYSTEM, with a creation timestamp reflecting the original `cmd.exe` binary age.

Sysmon EID 7 includes image loads for `WmiPrvSE.exe` with `wmiutils.dll` (tagged `T1047`) alongside the PowerShell .NET framework DLLs. This shows the WMI provider activating before the payload chain runs.

Security EID 4624 (logon), EID 4627 (group membership), and EID 4672 (special privileges assigned) appear in this dataset — reflecting the WMI service logon event for the NETWORK SERVICE session, a slightly richer security log than the other T1546.008 tests.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

The WMI command that initiated the chain — the original `Win32_Process.Create` call — is not present because WMI command execution events (Microsoft-Windows-WMI-Activity/Operational, EID 5861) are not a collected channel in this dataset. The WMI invocation appears only indirectly through the `WmiPrvSE.exe` process creation. There is no Sysmon EID 20/21/22/23 WMI event coverage. Object access auditing is disabled, so EID 4663/4660 events for the file overwrite are absent.

## Assessment

This dataset is valuable for two reasons. First, it captures the Magnify.exe binary replacement with the same high-fidelity process chain and file-create artifacts as the utilman.exe variant (test 6). Second, it uniquely demonstrates the WMI delivery vector: the `WmiPrvSE.exe` process creation and `wmiutils.dll` image load tagged on T1047 provide a detection anchor for WMI-originated accessibility abuse. Defenders can correlate the WMI process spawn with the subsequent takeown/icacls/copy chain. Adding WMI-Activity/Operational channel collection would fill the gap on the originating WMI command.

## Detection Opportunities Present in This Data

1. **Sysmon EID 11 — FileCreate for `C:\Windows\System32\Magnify.exe` written by `cmd.exe` as SYSTEM** — direct overwrite of a protected accessibility binary.
2. **Sysmon EID 1 — `takeown.exe /F C:\Windows\System32\Magnify.exe`** and `icacls.exe /grant Administrators:F` targeting an accessibility binary, tagged `T1222.001`.
3. **Sysmon EID 1 — `WmiPrvSE.exe -Embedding` spawning a child `cmd.exe`** that proceeds to modify System32 binaries — WMI-driven file tamper chain, tagged `T1047`.
4. **Sysmon EID 7 — `wmiutils.dll` load in `WmiPrvSE.exe`** immediately preceding the tamper chain — WMI activation indicator.
5. **Security EID 4624/4672 — NETWORK SERVICE logon with special privileges assigned**, temporally correlated with System32 file modification events — WMI service activation fingerprint.
6. **Sysmon EID 1 — `cmd.exe` command line containing `copy ... cmd.exe ... Magnify.exe`** — accessibility binary replacement payload signature.
