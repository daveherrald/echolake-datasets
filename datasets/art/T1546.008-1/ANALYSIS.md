# T1546.008-1: Accessibility Features — Attaches Command Prompt as a Debugger to a List of Target Processes

## Technique Context

T1546.008 (Accessibility Features) covers techniques that abuse Windows accessibility tools — programs designed to launch at the logon screen before authentication — to gain privileged access or persistence. The Image File Execution Options (IFEO) debugger method works by registering an arbitrary binary as the "debugger" for an accessibility binary under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>\Debugger`. When Windows attempts to launch the accessibility tool (e.g., by pressing Shift five times for Sticky Keys), it instead launches the registered debugger (commonly `cmd.exe` or PowerShell) as SYSTEM, with no user authentication required. This grants an attacker or insider a SYSTEM shell from the Windows login screen. The IFEO debugger technique has been used since at least 2009 and remains a reliable privilege escalation path. This test (T1 in the ART sequence) bulk-registers `cmd.exe` as the debugger for multiple accessibility binaries simultaneously.

## What This Dataset Contains

The dataset spans 6 seconds (2026-03-13 23:40:18–23:40:24) on ACME-WS02 running as NT AUTHORITY\SYSTEM.

**Sysmon (49 events, IDs: 1, 3, 7, 10, 11, 13, 17):** The core evidence is seven Sysmon ID=13 (RegistryValueSet) events, all fired in rapid succession, all tagged `technique_id=T1546.012,technique_name=Image File Execution Options Injection` by sysmon-modular. The events write `cmd.exe` as the Debugger for:

- `HKLM\...\Image File Execution Options\osk.exe\Debugger`
- `HKLM\...\Image File Execution Options\sethc.exe\Debugger`
- `HKLM\...\Image File Execution Options\utilman.exe\Debugger`
- `HKLM\...\Image File Execution Options\magnify.exe\Debugger`
- `HKLM\...\Image File Execution Options\narrator.exe\Debugger`
- `HKLM\...\Image File Execution Options\DisplaySwitch.exe\Debugger`
- `HKLM\...\Image File Execution Options\atbroker.exe\Debugger`

All seven are written by `powershell.exe` (PID 7108) in a single pass with the value `C:\windows\system32\cmd.exe`. The source Sysmon ID=1 shows the PowerShell command:

```
"powershell.exe" & {$input_table = ...
```

(the full command sets all IFEO keys programmatically).

**Security (14 events, IDs: 4624, 4627, 4672, 4688, 4689, 4703):** Uniquely, this dataset includes logon events: 4624 (logon type 5 — service logon), 4627 (group membership), and 4672 (special privileges). These appear to reflect a service account authentication event during or near the test, rather than the technique itself. The SYSTEM logon for the test framework is also visible. Security ID=4688 captures `whoami.exe` and `powershell.exe` process creations.

**PowerShell (51 events, IDs: 4103, 4104):** Test framework boilerplate plus additional module-level invocation events, but no technique-specific script block content beyond the `Set-ExecutionPolicy` wrapper.

## What This Dataset Does Not Contain

- **No accessibility feature trigger execution:** The IFEO keys are registered but no accessibility binary (sethc.exe, osk.exe, etc.) is launched to test the debugger substitution. There is no `cmd.exe` spawning from winlogon.exe or from an accessibility parent.
- **No file system modification to the accessibility binaries:** This test uses the IFEO method (registry only), not the file replacement method tested in T1546.008-2 and T1546.008-10.
- **No Sysmon ID=3 for technique-related network:** The only ID=3 event is a Windows Defender (`MsMpEng.exe`) network connection, not related to the technique.

## Assessment

This is a strong, immediately usable dataset for IFEO-based accessibility feature detections. The seven Sysmon ID=13 events provide a complete, structured, technique-tagged record of every key write. The bulk-write pattern (seven IFEO Debugger keys written within milliseconds by a single PowerShell process) is itself a high-confidence indicator separate from matching on individual key paths. The Security channel's logon events (4624/4627/4672) add context for the SYSTEM session but do not relate to the technique directly. The dataset would be complete for end-to-end testing if paired with a trigger phase showing the accessibility binary being invoked and `cmd.exe` spawning from winlogon or the logon session.

## Detection Opportunities Present in This Data

1. **Sysmon ID=13:** Any write to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<accessibility_binary>\Debugger` is a direct, high-fidelity indicator — this key has no legitimate use on workstations.
2. **Sysmon ID=13 (bulk pattern):** Multiple IFEO Debugger writes across different accessibility binaries (sethc.exe, osk.exe, utilman.exe, magnify.exe, narrator.exe) within milliseconds of each other, from a single process, is an automated bulk-registration pattern that warrants immediate investigation.
3. **Sysmon ID=1 / Security ID=4688:** PowerShell executing with a script block that sets `Image File Execution Options\Debugger` values is detectable via command-line matching even without registry event coverage.
4. **Sysmon ID=13 + ID=1 correlation:** A PowerShell process (ID=1) immediately followed by IFEO Debugger registry writes (ID=13) from the same process GUID ties the registration action to the specific execution context.
5. **Security ID=4688:** Any process creating another process where the parent is an accessibility binary (sethc.exe, osk.exe, utilman.exe) via winlogon.exe in session 0 or at the logon desktop is the post-trigger indicator this dataset lacks — useful for building the complementary detection.
