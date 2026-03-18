# T1574.001-2: DLL Search Order Hijacking — Phantom DLL Hijacking - WinAppXRT.dll

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes a variant known as **phantom DLL hijacking**, where the target DLL does not exist anywhere on the system. When a legitimate application attempts to load a non-existent DLL by name, Windows traverses the full search order looking for it. An adversary who plants a DLL with that name in any directory appearing early in the search path will have it loaded — with no legitimate copy anywhere to compete with.

This test targets `WinAppXRT.dll`, a DLL that some Windows components may attempt to load but which is not distributed with the OS. The attack copies `amsi.dll` to `%APPDATA%`, renames it to `WinAppXRT.dll`, places it into `C:\Windows\System32\`, and sets the registry value `HKEY_CURRENT_USER\Environment\APPX_PROCESS=1` as an additional environment marker. Because no real `WinAppXRT.dll` exists on the system, any process that searches for it will find the planted copy immediately.

## What This Dataset Contains

The dataset captures 127 events across four log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103), Security (18 events: 10 EID 4689, 6 EID 4688, 1 EID 4702, 1 EID 4703), Application (1 event: EID 16384), and Task Scheduler (1 event: EID 140). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The full attack sequence is visible through Security EID 4688.** The primary `cmd.exe` process was created from PowerShell with the complete attack chain in its command line:

```
"cmd.exe" /c copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll
          & ren %APPDATA%\amsi.dll WinAppXRT.dll
          & copy %APPDATA%\WinAppXRT.dll %windir%\System32\WinAppXRT.dll
          & reg add "HKEY_CURRENT_USER\Environment" /v APPX_PROCESS /t REG_EXPAND_SZ /d "1" /f
```

`reg.exe` was then spawned directly to complete the registry write:

```
Process Command Line: reg add "HKEY_CURRENT_USER\Environment" /v APPX_PROCESS /t REG_EXPAND_SZ /d "1" /f
Creator Process Name: C:\Windows\System32\cmd.exe
```

The cleanup phase is also captured — a separate `cmd.exe` process was created with:

```
"cmd.exe" /c reg delete "HKEY_CURRENT_USER\Environment" /v APPX_PROCESS /f
          & del %windir%\System32\WinAppXRT.dll
          & del %APPDATA%\WinAppXRT.dll
```

And a child `reg.exe` (PID 0x461c) executed `reg delete "HKEY_CURRENT_USER\Environment" /v APPX_PROCESS /f` to remove the registry artifact. All processes exited with status `0x0`.

Security EID 4702 (a scheduled task was updated) and Task Scheduler EID 140 both reference the `SvcRestartTask` for the Software Protection Platform — background OS activity coinciding with the test window, not part of the attack.

Application EID 16384 records the Software Protection service scheduling a restart — unrelated OS behavior.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 7 (Image Loaded), you cannot confirm from this dataset whether any process actually loaded `WinAppXRT.dll` from `System32` during the test window. The file was written there and the registry marker was set, but whether a susceptible application picked up the phantom DLL and loaded it is not captured here.

**No file creation events.** The `copy` and `ren` operations that place `WinAppXRT.dll` in System32 and AppData are only visible through the process command line, not as dedicated file write records.

**No network activity.** This technique involves no outbound connections and none are present.

**No Sysmon EID 12/13 (Registry events).** The `HKCU\Environment\APPX_PROCESS` registry key write is visible only through the `reg.exe` command line in EID 4688, not as a dedicated registry modification event.

## Assessment

The defended variant of this test recorded 40 Sysmon, 12 Security, and 34 PowerShell events. The undefended run produced 0 Sysmon, 18 Security, and 107 PowerShell events. The Security channel is richer here — six EID 4688 events compared to the defended run's process creation records — capturing both the attack phase and cleanup phase command lines in full.

The critical difference is that in the undefended run, `WinAppXRT.dll` was successfully written to `C:\Windows\System32\` and the registry key was set. In the defended variant, Defender blocked or flagged the DLL placement. Here, both operations complete cleanly. The phantom DLL now sits in System32 for the duration of the test. Whether any running process loaded it during that window remains unconfirmed without EID 7 data.

## Detection Opportunities Present in This Data

**EID 4688 — PowerShell spawning cmd.exe to copy a renamed system DLL into System32.** The command `copy %APPDATA%\WinAppXRT.dll %windir%\System32\WinAppXRT.dll` is anomalous — writing a user-space file into System32 from a PowerShell/cmd.exe chain running as SYSTEM.

**EID 4688 — reg.exe writing to `HKCU\Environment` with an unusual value name.** The key `APPX_PROCESS` under `HKCU\Environment` is not a standard Windows registry value. Any write to `HKCU\Environment` from a scripted context deserves scrutiny, as user environment variables persist across logons.

**EID 4688 — reg.exe deleting from `HKCU\Environment` immediately after a file placement.** Rapid creation and deletion of environment variables from within a scripted execution chain is consistent with post-exploitation cleanup.

**File placement of unknown DLL into System32.** Any write of a DLL with an unrecognized name into `C:\Windows\System32\` by a non-installer process is a high-fidelity indicator. The file `WinAppXRT.dll` does not appear in Windows update manifests or known software package databases.
