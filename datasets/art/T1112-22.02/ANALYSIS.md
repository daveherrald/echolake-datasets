# T1112-22: Modify Registry — Activate Windows NoFileMenu Group Policy Feature

## Technique Context

This test is the third in a consecutive series (T1112-19, T1112-21, T1112-22, T1112-24, T1112-27, T1112-28, T1112-30) targeting `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` via the `reg.exe` utility. The `NoFileMenu` value set to `1` removes the **File** menu from Windows Explorer (the file manager) when the user browses folders or the desktop using Explorer. This prevents users from performing file operations through the Explorer menu — copying, creating shortcuts, opening command prompts from Explorer's File menu — without touching the underlying file system permissions.

In practice, `NoFileMenu` is a niche Group Policy setting that primarily disrupts Explorer-based workflows rather than blocking underlying file system access via other means. It is most relevant in adversarial contexts as part of a coordinated restriction effort alongside other Explorer policy modifications, collectively degrading the victim's ability to navigate and manage the file system through familiar tools. Like the other Explorer policy modifications in this series, it applies per-user (HKCU) and persists across sessions.

The execution pattern is structurally identical to T1112-19 and T1112-21: `powershell.exe` → `cmd.exe /c reg add` → `reg.exe`. This consistency across tests makes the overall pattern — rather than any individual value name — the correct unit of detection.

## What This Dataset Contains

This dataset captures 114 events across three channels (93 PowerShell, 4 Security, 17 Sysmon) collected over a 4-second window (2026-03-14T23:49:17Z–23:49:21Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688):**

Four EID 4688 events:
1. `whoami.exe` — pre-test identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFileMenu /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFileMenu /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check

The NoFileMenu value name is the only meaningful command line difference from T1112-19 (NoRun) and T1112-21 (NoControlPanel).

**Sysmon Process Creates (EID 1):**

Four EID 1 events with complete process ancestry and hash data. The cmd.exe and reg.exe SHA256 and IMPHASH values are consistent with the other T1112 tests: cmd.exe SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`, reg.exe SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`. Parent PowerShell process is PID 1812 (GUID `{9dc7570a-f3fc-69b5-a611-000000000600}`).

**Sysmon Named Pipe Create (EID 17):**

One EID 17 event creates a named pipe for the parent PowerShell process: `\PSHost.134180057560207708.1812.DefaultAppDomain.powershell`. The PID embedded in the pipe name (`1812`) matches the Sysmon EID 1 parent PowerShell process, providing an additional cross-event correlation point.

**Sysmon Image Loads (EID 7):**

9 EID 7 events for the .NET CLR DLL load sequence on the parent PowerShell process (PID 1812).

**Sysmon Process Access (EID 10):**

3 EID 10 events showing the parent PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.

**PowerShell Script Block Logging (EID 4104):**

93 EID 4104 events, all PowerShell runtime boilerplate.

## What This Dataset Does Not Contain

- **Sysmon EID 13 (Registry Value Set):** As with the other Explorer policy key tests, direct registry write events are not captured by the Sysmon configuration for this path.
- **NoFileMenu effect on the user interface:** Windows does not generate a log event when the File menu restriction takes effect.
- **Any network activity:** This technique involves no network communication.
- **File system changes beyond registry:** No files are created, modified, or deleted by this technique.

## Assessment

T1112-22 is the most structurally routine dataset in this series — identical execution pattern, same binary chain, same target path, different value name. The event count (114) and composition are essentially the same as T1112-19 (114 events). This consistency across tests is actually an asset: it confirms that these datasets are suitable for evaluating detection logic against the pattern family rather than just individual test signatures.

The primary forensic value of this dataset, compared to the defended variant (76 events: 35 PowerShell, 13 Security, 28 Sysmon), is in showing the execution completed without interruption. The undefended variant has more PowerShell events (93 vs. 35) and fewer Security events (4 vs. 13) — the same pattern seen consistently across this series, driven by Defender's own process activity in the defended variant.

The named pipe name `\PSHost.134180057560207708.1812.DefaultAppDomain.powershell` includes the PowerShell process PID (1812) and a timestamp-based identifier that can be cross-correlated with the Sysmon EID 1 record for PID 1812, providing timeline reconstruction capability without relying on process GUIDs alone.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — NoFileMenu in reg add Command:**
The command targeting `HKCU\...\Policies\Explorer` with value `NoFileMenu` and DWORD `1` is detectable as a specific instance. The broader path pattern (`reg add` to any value under `...\Policies\Explorer`) provides family-level coverage.

**Sysmon EID 17 — PowerShell Named Pipe with PID:**
The named pipe `\PSHost.{timestamp}.{pid}.DefaultAppDomain.powershell` is created for every PowerShell process. Correlating the PID embedded in the pipe name with Sysmon EID 1 process create records provides a reliable way to link named pipe creation to the spawning process without relying on ProcessGUID joins.

**EID 4688 Process Chain Pattern — PowerShell→cmd→reg:**
The three-step chain (PowerShell spawning cmd.exe with a `/c reg add` argument, followed by reg.exe) is a detectable execution pattern for registry modifications. This pattern applies regardless of which specific registry path is targeted and is more durable than value-name-specific matching.

**Sysmon EID 10 — Process Access from PowerShell to cmd/reg:**
The parent PowerShell accessing its child processes with `GrantedAccess: 0x1FFFFF` is standard subprocess management behavior. When correlated with the child process performing suspicious registry modifications, this EID 10 pattern provides parent-child attribution even if the EID 4688 parent process field is populated with only a PID (which can be reused across reboots).
