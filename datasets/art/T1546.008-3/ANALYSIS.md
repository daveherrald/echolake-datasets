# T1546.008-3: Accessibility Features — Create Symbolic Link From osk.exe to cmd.exe

## Technique Context

T1546.008 (Accessibility Features) covers the abuse of Windows accessibility programs — On-Screen Keyboard (osk.exe), Utility Manager (utilman.exe), Magnifier (Magnify.exe), Narrator (narrator.exe), Display Switch (DisplaySwitch.exe), and others — as persistence or privilege escalation vectors. These programs are launched by the Windows logon screen before any user authenticates, typically by Winlogon running as SYSTEM. If an attacker replaces or links one of these binaries to a shell or implant, they obtain a SYSTEM-level process accessible from the lock screen with no credentials required. This technique has been used by APT groups and is well-known enough that Microsoft has introduced virtualization-based protection (Credential Guard) and Windows Defender features that partially address it. Detection focuses on file modifications to `%windir%\System32\` accessibility binaries, symbolic link creation from those paths, and on the use of intermediate permission-changing tools (`takeown`, `icacls`) preceding those writes.

## What This Dataset Contains

The test creates a symbolic link from `osk.exe` to `cmd.exe` using a multi-step command executed by `cmd.exe` (PID 2344) spawned from `powershell.exe` (PID 6480) running as `NT AUTHORITY\SYSTEM`. The full command line captured in Sysmon EID 1 shows the complete attack chain in a single cmd.exe invocation:

```
"cmd.exe" /c IF NOT EXIST %windir%\System32\osk.exe.bak (copy %windir%\System32\osk.exe %windir%\System32\osk.exe.bak) ELSE ( pushd ) & takeown /F %windir%\System32\osk.exe /A & icacls %windir%\System32\osk.exe /grant Administrators:F /t & del %windir%\System32\osk.exe & mklink %windir%\System32\osk.exe %windir%\System32\cmd.exe
```

Sysmon EID 11 (FileCreate) captures the backup file being written: `C:\Windows\System32\osk.exe.bak` (created by `cmd.exe`, PID 2344). The mklink creation of the symlink itself does not appear as a separate EID 11 file-create — the symlink landing point is recorded implicitly when cmd.exe performs the copy step.

Sysmon EID 1 also shows `whoami.exe` executed from the same parent PowerShell process as post-execution verification. Security EID 4688 records both the `whoami.exe` and the `cmd.exe` process creations under the SYSTEM account.

The PowerShell channel (EID 4103, 4104) contains only the ART test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` module invocations and `Set-StrictMode` blocks. No technique-specific PowerShell script content appears because the technique is executed via cmd.exe, not a PowerShell cmdlet.

The Application channel carries a single EID 15: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`, a routine Defender health check, not related to the technique.

## What This Dataset Does Not Contain

The dataset does not include a Sysmon EID 11 event for the symlink target itself at `C:\Windows\System32\osk.exe` — Windows symbolic link creation via `mklink` does not produce a FileCreate event the same way a regular file write does. There is no EID 11 with `TargetFilename: C:\Windows\System32\osk.exe` representing the link.

Sysmon EID 1 does not capture `takeown.exe`, `icacls.exe`, or `del` as separate process-create events. The sysmon-modular include-mode config matched the `cmd.exe` invocation on the `T1083` rule but the child `takeown.exe` and `icacls.exe` processes fell outside the include-rule set. Security EID 4688 similarly does not show `takeown` or `icacls` — those processes exit too quickly and do not generate 4688 events in this dataset. Object access auditing is not enabled, so there are no EID 4663/4660 (file permission change / delete) events.

## Assessment

This is a strong dataset for the binary file-tamper and symlink creation sub-variant. The attack-chain command line is fully preserved in a single Sysmon EID 1 `Message` field, providing a complete picture of the approach. The missing coverage for `takeown` and `icacls` as separate processes is a minor gap, but for detection purposes the parent `cmd.exe` command line contains all of the semantically interesting arguments. Adding Security object access auditing on `%windir%\System32\` would surface EID 4660/4663 events, and Sysmon file-create monitoring of `.bak` files in System32 would strengthen the dataset further.

## Detection Opportunities Present in This Data

1. **Sysmon EID 1 — cmd.exe command line containing `mklink` referencing an accessibility binary path** (`%windir%\System32\osk.exe`) alongside `takeown` and `icacls` in a single command, parent `powershell.exe` running as SYSTEM.
2. **Sysmon EID 11 — FileCreate for a `.bak` backup of an accessibility binary** (`osk.exe.bak`) written to `C:\Windows\System32\` by `cmd.exe` as SYSTEM — indicates pre-tamper backup step.
3. **Security EID 4688 — cmd.exe process creation as NT AUTHORITY\SYSTEM from a PowerShell parent** with a command line referencing accessibility tool paths in System32.
4. **Sysmon EID 1 — `whoami.exe` spawned from `powershell.exe` as SYSTEM immediately following the tamper sequence** — post-exploitation verification pattern.
5. **Cross-event correlation: cmd.exe EID 1 with accessibility binary path + EID 11 .bak file creation within seconds** — high-confidence behavioral cluster.
