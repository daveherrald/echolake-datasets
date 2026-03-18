# T1518-1: Software Discovery — Find and Display Internet Explorer Browser Version

## Technique Context

T1518 (Software Discovery) covers adversary enumeration of installed software to inform subsequent actions — selecting compatible exploits, identifying vulnerable versions, assessing what security tools are present, and understanding the target environment. Querying the IE version via the registry is a classic initial-access and post-compromise reconnaissance step. Attackers use registry queries against `HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer` because IE version data historically correlated with patch levels and exploit applicability. Even on systems where IE has been removed, the registry keys may remain, making this a lightweight probe that does not require spawning IE itself.

## What This Dataset Contains

The test executes `reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion` via `cmd.exe /c`. Two process-create chains are visible.

**Sysmon (Event ID 1, `technique_id=T1059.003`)** — `cmd.exe` is captured with the full command line:
```
"cmd.exe" /c reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
```
Parent: `powershell.exe` (the ART test framework).

**Sysmon (Event ID 1, `technique_id=T1012`)** — `reg.exe` is captured as a child of the `cmd.exe` above:
```
reg  query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
```
The sysmon-modular config tagged this with `T1012` (Query Registry), which is accurate — `reg.exe query` is the canonical Query Registry tool. Both hashes are recorded for `reg.exe` (SHA256=411AE446…).

**Security (Event ID 4688)** — Process creates for `whoami.exe`, `cmd.exe`, and `reg.exe` all appear in the security log with command lines (command-line auditing is enabled). The `cmd.exe` event includes the full `reg query` argument.

**Security (Event IDs 4689, 4703)** — Process exits and a token right adjustment for `powershell.exe` enabling elevated privileges including `SeBackupPrivilege` and `SeRestorePrivilege` are recorded.

**PowerShell (Event IDs 4103, 4104)** — The PowerShell channel contains only test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` and the standard `Set-StrictMode` error-formatter fragments. No technique-relevant script blocks appear because the technique was executed via `cmd.exe`, not a PowerShell cmdlet.

## What This Dataset Does Not Contain

- No output of the `reg query` command. Event logs do not capture stdout; you cannot see the actual IE version value returned. Object access auditing (registry read) is not enabled, so no 4663 events exist for the registry key read.
- No Sysmon Event 12/13 — this is a read operation, not a registry write.
- The IE version query target key is for reconnaissance only; there are no follow-on events showing exploitation or decision-making based on the result.

## Assessment

This is a minimal but clean dataset. The process chain (`powershell.exe` → `cmd.exe` → `reg.exe`) with full command lines captured in both Sysmon and Security logs provides everything needed to build a detection. The sysmon-modular rule correctly tagged `reg.exe` with T1012. For a discovery technique of this simplicity the dataset is appropriately scoped, though it would be stronger with registry object access auditing enabled to confirm the key was successfully read.

## Detection Opportunities Present in This Data

1. **Sysmon Event 1 / Security 4688** — `reg.exe query` targeting `HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer` is a strong indicator, particularly when spawned from PowerShell or a non-interactive session.
2. **Sysmon Event 1 with `technique_id=T1012`** — The rule annotation is present and usable for triage without custom rule development.
3. **Process chain anomaly** — `powershell.exe` (SYSTEM) → `cmd.exe /c reg query` is not standard workstation activity; the intermediate `cmd.exe` wrapper is a behavioral indicator even before inspecting the argument.
4. **Security 4688 correlation** — Correlating a `whoami.exe` invocation (process execution context check) followed immediately by a `reg.exe query` IE version check from the same parent PowerShell session indicates reconnaissance sequencing.
5. **Sysmon Event 1 `reg.exe` parent check** — `reg.exe` spawned by `cmd.exe` which was spawned by `powershell.exe` at SYSTEM integrity is anomalous on a domain workstation; legitimate IT scripts typically run under a service account or user context.
