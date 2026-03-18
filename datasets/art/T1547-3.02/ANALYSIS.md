# T1547-3: Boot or Logon Autostart Execution — Leverage Virtual Channels to Execute Custom DLL During Successful RDP Session

## Technique Context

T1547 covers Boot or Logon Autostart Execution. This test exercises a persistence mechanism through RDP Virtual Channel Add-ins. Windows Terminal Services allows custom DLLs to be registered as virtual channel add-ins in the registry under `HKCU\Software\Microsoft\Terminal Server Client\Default\Addins\<name>`, with a `Name` value pointing to a DLL path. These DLLs are loaded into the RDP client process (`mstsc.exe`) when the user initiates an RDP connection.

An adversary who establishes this registry entry causes their DLL to be loaded whenever the compromised user connects via RDP — making this a logon-triggered persistence mechanism that fires specifically on RDP usage. The entry is user-specific (HKCU), requires no administrative privilege to create, and is not monitored by many EDR configurations focused on more common Run key paths.

The test registers `C:\Windows\System32\amsi.dll` as the add-in DLL (a benign system DLL used as a stand-in for a malicious payload), then removes it in the cleanup phase. The full registration lifecycle — creation and deletion — is captured in this dataset.

The undefended dataset (21 Sysmon events) is slightly larger than the defended variant (17 Sysmon events), likely because the defended environment's Defender process scanning activity suppressed some EID 7 DLL load events in the recorded window.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17 17:08:33–17:08:37 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (21 events — Event IDs 1, 7, 10, 11, 17):**

Sysmon EID 1 (ProcessCreate, 6 events) records the complete registration and cleanup chain:

1. `whoami.exe` — test framework context check, tagged `technique_id=T1033`
2. `cmd.exe` — tagged `technique_id=T1059.003`:
   ```
   "cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware" /v Name /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f
   ```
3. `reg.exe` — tagged `technique_id=T1012` (Query Registry — the sysmon-modular label fires on `reg.exe` regardless of operation type):
   ```
   reg  add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware" /v Name /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f
   ```
4. `whoami.exe` — second test framework context check
5. `cmd.exe` (cleanup):
   ```
   "cmd.exe" /c reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware" /f
   ```
6. `reg.exe` (cleanup):
   ```
   reg  delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware" /f
   ```

Both the creation and deletion of the add-in registry key are captured in Sysmon EID 1, providing the full lifecycle. The registry key name `Malware` is the literal value used by the ART test.

Sysmon EID 7 (ImageLoad, 9 events) records .NET runtime and Defender DLLs into the test framework PowerShell instances.

Sysmon EID 10 (ProcessAccess, 4 events) records `powershell.exe` accessing `whoami.exe` and `cmd.exe` child processes.

Sysmon EID 11 (FileCreate, 1 event) records PowerShell startup profile data.

Sysmon EID 17 (PipeCreate, 1 event) records the PowerShell named pipe.

**No Sysmon EID 13 (RegistrySetValue)** events are present. The registry write was performed by `reg.exe`, and the sysmon-modular include configuration did not capture value writes to the `Terminal Server Client\Default\Addins\` key path in this ruleset.

**Security (6 events — Event ID 4688):**

Six process creation events covering `whoami.exe`, `cmd.exe` (add operation), `reg.exe` (add operation), `whoami.exe` (second check), `cmd.exe` (delete operation), and `reg.exe` (delete operation). The Security channel mirrors the Sysmon EID 1 capture and provides independent confirmation of the full command lines.

**PowerShell (107 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the test script, which includes the `cmd.exe /c reg add` command as a string passed to `cmd.exe`. The full registry key path and value (`C:\Windows\System32\amsi.dll`) appear verbatim in the ScriptBlock record.

## What This Dataset Does Not Contain

- **No Sysmon EID 13 (RegistrySetValue):** The write of the `Name` value under `HKCU\Software\Microsoft\Terminal Server Client\Default\Addins\Malware` is not captured as a registry event. Sysmon EID 12 (RegistryObjectAddedOrDeleted) is also absent — the key creation and deletion by `reg.exe` are not within the sysmon-modular include patterns for this path.
- **No RDP session trigger:** The dataset captures the persistence setup only. The DLL would be loaded when the user initiates an RDP connection from this machine. No RDP session was initiated, so no `mstsc.exe` execution or DLL load is present.
- **No AMSI.dll load into mstsc.exe:** Even if an RDP session were initiated, the dataset would need to capture `mstsc.exe` loading `amsi.dll` via Sysmon EID 7 to confirm the persistence mechanism fired.

## Assessment

This dataset provides clear evidence of the registration pattern through process-level telemetry, even in the absence of registry-specific events. The complete `reg add` command line — including the exact key path `HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\Malware` and the DLL value `C:\Windows\System32\amsi.dll` — is captured in both Sysmon EID 1 and Security EID 4688. The cleanup phase is also fully represented, making this one of the few datasets where both the installation and removal of a persistence artifact are visible.

The absence of Sysmon EID 13 highlights a coverage gap for this specific key path. Detection relying on registry monitoring would miss the write event; process-based detection of `reg.exe add ... Terminal Server Client ... Addins` remains viable.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688:** `reg.exe add` targeting `HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\`. Any write to this key path, particularly with a `Name` value pointing to a DLL outside the system's expected RDP add-in set, is a high-confidence indicator.
- **Sysmon EID 1 / Security EID 4688:** `cmd.exe /c reg add ... Addins\Malware` where the add-in name is explicitly `Malware`. Real-world attacks would use a less obvious name, but the key path and DLL value pattern remain consistent.
- **Security EID 4688:** `reg.exe` spawned by `cmd.exe` which was spawned by `powershell.exe` in SYSTEM context, targeting `Terminal Server Client\Addins`. The three-level chain (PowerShell → cmd → reg) for a single registry write is characteristic of scripted attack tooling rather than normal user or administrative activity.
- **PowerShell EID 4104:** The full `cmd.exe /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default\Addins\..."` command string appears verbatim in ScriptBlock logging, enabling string-based matching in the PowerShell channel even without process or registry-specific events.
