# T1547.001-2: Registry Run Keys / Startup Folder — Reg Key RunOnce

## Technique Context

MITRE ATT&CK T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. The `RunOnceEx` subkey under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion` is a lesser-used variant of the `RunOnce` mechanism. Entries placed in `RunOnceEx` execute once at logon and are then deleted by the system. Unlike the standard `RunOnce` key, `RunOnceEx` supports dependency ordering and DLL loading via structured subkeys — making it useful to adversaries who want to register a DLL to execute at the next logon without using a persistent run key.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that adds a value to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend` using the `reg.exe` command-line tool. The test simulates an adversary registering a DLL path (`C:\Path\AtomicRedTeam.dll`) for execution at next user logon.

**Sysmon (18 events):**
- EID 1 (Process Create): `whoami.exe` spawned by PowerShell (test framework identity check), `cmd.exe` spawned by PowerShell with the full `reg add` command line targeting `RunOnceEx\0001\Depend`, and `reg.exe` as a child of `cmd.exe` executing the registry write.
- EID 7 (Image Load): PowerShell loading .NET runtime and several DLLs flagged with T1055 and T1574.002 rule names — this is standard PowerShell startup behavior, not separate suspicious activity.
- EID 10 (Process Access): PowerShell accessing `whoami.exe` with `GrantedAccess: 0x1FFFFF` — an artifact of the ART test framework invoking `whoami` as a pre-execution identity check.
- EID 11 (File Create): PowerShell profile/startup data file written.
- EID 13 (Registry Value Set): `reg.exe` setting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\1` to `C:\Path\AtomicRedTeam.dll`. Rule name annotated as `technique_id=T1547.001`.
- EID 17 (Pipe Create): Named pipe created by PowerShell process.

**Security (10 events):**
- EID 4688/4689: Process creation and exit records for `powershell.exe`, `whoami.exe`, `cmd.exe`, and `reg.exe`. The 4688 event for `cmd.exe` includes the full command line: `cmd.exe /c REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"`. The `reg.exe` event shows the same argument set.
- EID 4703 (Token Right Adjusted): PowerShell token privilege adjustment — routine test framework activity.

**PowerShell (35 events):**
- EID 4103 (Module Logging): `Set-ExecutionPolicy -Scope Process -Force` — standard ART test framework preamble run twice per execution.
- EID 4104 (Script Block Logging): The bulk of events are inline error-handling scriptblocks emitted by the PowerShell runtime (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, etc.). These are boilerplate emitted during PowerShell module loading. The actual ART test logic (`reg add` via `cmd.exe`) does not appear as a distinct 4104 scriptblock because it is executed inline as a shell command rather than as a PowerShell script.

## What This Dataset Does Not Contain

- No registry modification event is present in the Security log (object access auditing is disabled in the audit policy).
- There is no Sysmon EID 13 event for a standard `HKCU\...\Run` or `HKCU\...\RunOnce` path — this test specifically targets `RunOnceEx`, which is less commonly covered by detection rules.
- The dataset does not include any execution of the registered DLL — the test only creates the persistence entry; no logon cycle occurred to trigger it.
- No network connection events (Sysmon EID 3) are present in this dataset.
- The ART test framework script body does not appear as a 4104 scriptblock — only the surrounding boilerplate is captured.

## Assessment

The test completed successfully. Sysmon EID 13 directly records the `RunOnceEx` registry write with the target object and value, providing a reliable indicator. The Security log's EID 4688 events capture the full command line for both `cmd.exe` and `reg.exe`, offering a second detection surface. Windows Defender did not block this operation — `RunOnceEx` manipulation via `reg.exe` is not flagged by Defender in its current configuration.

The 35 PowerShell events are overwhelmingly boilerplate. Analysts working with this dataset should be aware that the majority of 4104 events carry no test-specific content; the meaningful process activity is in the Sysmon and Security logs.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: Registry write to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\*` by `reg.exe` or any non-system process. Sysmon's sysmon-modular configuration annotates this with `technique_id=T1547.001`.
- **Security EID 4688**: `reg.exe` process creation with command line containing `RunOnceEx` in the arguments. Parent process is `cmd.exe` spawned by `powershell.exe`.
- **Process chain**: `powershell.exe` → `cmd.exe` → `reg.exe` with `RunOnceEx` in the command line is a high-fidelity pattern.
- **Key path specificity**: The `RunOnceEx` path is rarely written to by legitimate software and warrants investigation whenever it appears in process command lines or registry event logs.
