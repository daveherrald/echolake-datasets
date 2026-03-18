# T1548.002-7: Bypass User Account Control — Bypass UAC using sdclt DelegateExecute

## Technique Context

T1548.002 (Bypass User Account Control) encompasses multiple auto-elevating Windows binaries that can be hijacked through HKCU registry manipulation. This test targets `sdclt.exe` (Windows Backup and Restore), which checks `HKCU\Software\Classes\Folder\shell\open\command` for a `DelegateExecute` value before auto-elevating. By writing a command string and an empty `DelegateExecute` value to that registry path, an attacker causes `sdclt.exe` to invoke the payload at high integrity without displaying a UAC prompt.

The key distinction from tests 3–5 (which target the `ms-settings` handler) is the use of the `Folder` COM shell extension rather than `ms-settings`. Detection rules written specifically to watch `ms-settings\shell\open\command` will not catch this variant. Defenders who tune on the `ms-settings` path need a separate rule for the `Folder` path, or a generalized rule covering any HKCU `Software\Classes` DelegateExecute manipulation.

The payload is a PowerShell child process that writes `cmd.exe /c notepad.exe` as the command value and then launches `sdclt.exe` directly. In a defended environment, Defender does not block the registry manipulation or sdclt launch, but the cleanup window is captured.

## What This Dataset Contains

The dataset spans approximately six seconds of telemetry (2026-03-17T17:17:40Z–17:17:46Z) across four log sources, with 145 total events.

**Security EID 4688 — five process creates recorded:**
The full execution chain is visible. From parent `powershell.exe` (PID 0x437c), the test framework spawns:
1. `whoami.exe` (PID 0x3ac4) — ART pre-check
2. Attack `powershell.exe` child (PID 0x3170) — the registry manipulation payload
3. `sdclt.exe` (PID 0x3f88) — launched from the attack PowerShell with `TokenElevationTypeDefault (1)`
4. `whoami.exe` (PID 0x400c) — post-execution check
5. A second `powershell.exe` (PID 0x39d0) — likely the cleanup invocation

The `sdclt.exe` process creation (PID 0x3f88) is explicitly recorded:
```
New Process Name: C:\Windows\System32\sdclt.exe
Token Elevation Type: TokenElevationTypeDefault (1)
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "C:\Windows\system32\sdclt.exe"
```
This is the pivotal event — it documents that `sdclt.exe` was launched programmatically from PowerShell, which has no legitimate administrative justification.

**Sysmon EID breakdown — 36 events: 24 EID 7, 4 EID 1, 4 EID 10, 2 EID 13, 2 EID 17:**
- EID 13 (Registry Value Set): Two events confirm the `Folder\shell\open\command` writes — the `DelegateExecute` empty value and the `(Default)` command string set to `cmd.exe /c notepad.exe`. These are the defining artifacts separating this technique from the `ms-settings` variants.
- EID 1 (Process Create): Four process creation events are logged including `sdclt.exe` (tagged `technique_id=T1218,technique_name=System Binary Proxy Execution`) and `whoami.exe` (tagged `T1033`). The `sdclt.exe` process create in Sysmon provides the same signal as Security 4688 but with richer metadata including hashes and integrity level.
- EID 10 (Process Access): Four events showing the test framework PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.
- EID 7 (Image Load): 24 events for PowerShell DLL startup sequence, identical in structure to T1548.002-5.

**PowerShell — 100 events: 97 EID 4104, 3 EID 4103:**
The EID 4104 script block log captures the attack payload. The full invocation block is recorded:
```
"powershell.exe" & {
  New-Item -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command"
           -Value 'cmd.exe /c notepad.exe'
  New-ItemProperty -Force -Path "HKCU:\Software\Classes\Folder\shell\open\command"
                   -Name "DelegateExecute"
  Start-Process -FilePath $env:windir\system32\sdclt.exe
  Start-Sleep -s 3
}
```
The EID 4103 module log records the `New-Item` and `New-ItemProperty` cmdlet invocations with full parameter bindings, including the resolved `HKCU:\Software\Classes\Folder\shell\open\command` path and the `DelegateExecute` name explicitly.

**Application — 4 EID 15 events:**
Routine Windows Defender status state-machine events, not technique-related.

## What This Dataset Does Not Contain

This dataset does not contain an event showing the elevated process spawned by `sdclt.exe`. The payload (`cmd.exe /c notepad.exe`) would open Notepad at high integrity, but since `notepad.exe` is a GUI application that exits quickly in a headless environment, any resulting child process creation may fall outside the capture window.

No Security EID 4634/4647 logoff events appear. The execution context is SYSTEM throughout (QEMU guest agent), so no separate logon session is created for the elevated process.

There is no Sysmon EID 3 (Network Connection) — this technique is entirely local and requires no network activity.

## Assessment

This dataset provides clean, complete evidence of the `sdclt.exe` DelegateExecute UAC bypass. The combination of Sysmon EID 13 registry writes to `Folder\shell\open\command`, the Security EID 4688 record showing `sdclt.exe` spawned from `powershell.exe`, and the PowerShell EID 4104 script block logging the full payload gives you three independent detection opportunities that fire before, during, and at execution. The undefended variant confirms execution proceeded without interference. Compared to the defended dataset (28 Sysmon, 11 Security, 39 PowerShell events), this run produces comparable Sysmon depth but fewer Security events in the capture window, reflecting slight differences in collection timing rather than missing artifacts. The `Folder\shell\open\command` registry path is the key differentiator from the `ms-settings` variant datasets.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 with `TargetObject` matching `\Software\Classes\Folder\shell\open\command` and event type `SetValue` — this path has no legitimate reason to be modified by a user process in normal operation.

2. Security EID 4688 showing `sdclt.exe` with `Creator Process Name` being a script interpreter (`powershell.exe`, `wscript.exe`, `cmd.exe`) rather than an interactive user session — programmatic invocation of `sdclt.exe` is anomalous.

3. Sysmon EID 1 for `sdclt.exe` tagged with `T1218` (System Binary Proxy Execution) — this Sysmon config already annotates this binary's abuse, providing a ready-made higher-level classification signal.

4. PowerShell EID 4103 recording `New-ItemProperty` with `Name = DelegateExecute` targeting any `HKCU:\Software\Classes\` path — the `DelegateExecute` value name in HKCU COM handlers is a near-universal indicator across all UAC bypass variants in this technique family.

5. PowerShell EID 4104 containing the string `DelegateExecute` combined with `Folder\shell\open\command` or `ms-settings\shell\open\command` — either path with this value name is a high-confidence indicator.

6. Temporal correlation: Sysmon EID 13 writing `HKCU\Software\Classes\Folder\shell\open\command` followed within seconds by a Security EID 4688 for `sdclt.exe` — the time delta between registry write and binary launch is typically under one second for scripted execution.
