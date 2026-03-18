# T1546.010-1: AppInit DLLs — Install AppInit Shim

## Technique Context

T1546.010 (AppInit DLLs) is a persistence mechanism that uses the `AppInit_DLLs` registry value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\`. When `LoadAppInit_DLLs` is set to `1`, Windows loads every DLL listed in `AppInit_DLLs` into any process that loads `user32.dll`. Because nearly every GUI application loads `user32.dll`, this is an extremely broad injection hook — the malicious DLL runs in the context of browsers, Office applications, and many system processes. The technique was partially mitigated in Windows 8+ when Secure Boot is enabled (the key is ignored when `RequireSignedAppInit_DLLs` is set), but it remains exploitable on systems without Secure Boot enforcement. Detection focuses on modifications to the `AppInit_DLLs` and `LoadAppInit_DLLs` registry values, and on DLL files referenced from those values.

## What This Dataset Contains

The test imports a pre-crafted `.reg` file to set the `AppInit_DLLs` values. Sysmon EID 13 captures two registry writes from `reg.exe` (`reg.exe import "C:\AtomicRedTeam\atomics\T1546.010\src\T1546.010.reg"`):

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
Details: C:\Tools\T1546.010.dll,C:\Tools\T1546.010x86.dll
RuleName: technique_id=T1546.010,technique_name=Appinit DLLs

TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
Details: DWORD (0x00000001)
RuleName: technique_id=T1546.010,technique_name=Appinit DLLs
```

Both values are written simultaneously by the same `reg.exe` process — `LoadAppInit_DLLs` is set to `1` (enabled) alongside the DLL paths.

Sysmon EID 1 shows the process chain: `whoami.exe`, `cmd.exe` (`CommandLine: "cmd.exe" /c reg.exe import "C:\AtomicRedTeam\atomics\T1546.010\src\T1546.010.reg"`, tagged `T1059.003`), and `reg.exe` (`CommandLine: reg.exe import "C:\AtomicRedTeam\atomics\T1546.010\src\T1546.010.reg"`, tagged `T1012`).

Security EID 4688 records three process creations as SYSTEM. EID 4689 records eight terminations. One EID 4703 (token right adjustment) is present.

The PowerShell channel contains only test framework boilerplate.

## What This Dataset Does Not Contain

The DLLs referenced (`C:\Tools\T1546.010.dll`, `C:\Tools\T1546.010x86.dll`) are not created during this test — the `.reg` import only registers the paths; whether the files actually exist at those paths is not captured. There are no Sysmon EID 11 events for DLL file creation. No DLL loads (EID 7) from `C:\Tools\` appear because no new GUI processes are spawned within the test window that would trigger AppInit loading. The impact of the `LoadAppInit_DLLs=1` setting is deferred to subsequent process launches.

The `WOW6432Node` mirror of `AppInit_DLLs` (which applies to 32-bit processes on a 64-bit system) may also be written by the import, but is not captured in the EID 13 events — only the 64-bit path is recorded.

## Assessment

This dataset provides clean, direct coverage of the AppInit DLL persistence registration step. The two Sysmon EID 13 events are correctly tagged with `technique_id=T1546.010` and show both the DLL paths and the `LoadAppInit_DLLs` enablement in a single write operation. The `reg.exe import` delivery method (loading from a `.reg` file) is noteworthy — it is slightly less common than `reg add` and may evade detections that only look for `reg add` command arguments. Strengthening this dataset would require adding DLL file creation events and capturing a process that loads the DLL post-persistence to demonstrate the injection phase.

## Detection Opportunities Present in This Data

1. **Sysmon EID 13 — RegistryValueSet to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`** with non-empty DLL paths, tagged `T1546.010`.
2. **Sysmon EID 13 — RegistryValueSet to `LoadAppInit_DLLs` set to `DWORD 0x00000001`** — enablement of AppInit loading; detection of this write alone is a high-fidelity signal on most enterprise systems.
3. **Sysmon EID 1 — `reg.exe import` with a `.reg` file path containing `AtomicRedTeam` or an unexpected temp/tools directory** — `.reg` file import delivery of persistence configuration.
4. **Sysmon EID 1 — `cmd.exe /c reg.exe import`** as SYSTEM from a PowerShell parent — unusual invocation pattern for registry import in a production environment.
5. **Security EID 4688 — `reg.exe` as SYSTEM with `import` argument** — complements Sysmon coverage for environments without Sysmon registry monitoring.
6. **Correlation: simultaneous EID 13 writes to both `AppInit_DLLs` and `LoadAppInit_DLLs`** by the same process within the same millisecond — atomic persistence setup, very specific to this technique.
