# T1505.004-1: IIS Components — Install IIS Module using AppCmd.exe

## Technique Context

T1505.004 (IIS Components) covers adversary abuse of Internet Information Services extensibility to achieve persistent server-side code execution. IIS supports native modules (DLLs loaded into the worker process) and managed modules (.NET assemblies). Attackers register their own DLL as an IIS module so that it is loaded every time a web request is processed, giving them a backdoor that survives service restarts and system reboots without requiring a scheduled task or registry run key. APT groups, including those targeting government and financial sector web servers, have exploited this path because IIS modules execute under the IIS worker process identity and blend in with legitimate web server activity. Detection engineering focuses on `appcmd.exe install module` invocations, writes to `%windir%\System32\inetsrv\config\applicationHost.config`, and DLL image loads into `w3wp.exe`.

## What This Dataset Contains

The test invokes `appcmd.exe install module /name:DefaultDocumentModule_Atomic /image:%windir%\system32\inetsrv\defdoc.dll` through a PowerShell-spawned `cmd.exe`. The key evidence chain is:

**Security (Event ID 4688)** — Two process-create events carry the full command line:
- `powershell.exe` (parent) spawning `cmd.exe` with the literal `appcmd.exe install module /name:DefaultDocumentModule_Atomic /image:%windir%\system32\inetsrv\defdoc.dll` argument.
- `cmd.exe` exits with status `0x1`, indicating the IIS role was not installed and appcmd failed — but the attempt telemetry is preserved.

**Sysmon (Event ID 1)** — Two `ProcessCreate` events are captured, both tagged with sysmon-modular rule annotations:
- `whoami.exe` (ART test framework pre-check, tagged `technique_id=T1033`)
- `cmd.exe` with the appcmd module installation command (tagged `technique_id=T1083`)

The Sysmon config matched `cmd.exe` here because the command line contains `inetsrv\appcmd.exe`, which overlaps with file-and-directory discovery rules in sysmon-modular.

**Sysmon (Event IDs 7, 10, 17)** — DLL image loads into `powershell.exe`, process access events, and named pipe events are present and provide supporting context on the PowerShell process involved in the invocation chain.

**PowerShell (Event IDs 4103, 4104)** — The channel contains only test framework boilerplate: `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` and repetitive `Set-StrictMode` error-formatter scriptblocks. No technique-specific PowerShell script blocks were logged because the actual technique was executed via `cmd.exe /c`, not a PowerShell cmdlet.

## What This Dataset Does Not Contain

- No actual `appcmd.exe` process-create event appears. The Sysmon include-mode filter did not match `appcmd.exe` itself (only `cmd.exe` that invoked it was captured). Security 4688 shows `cmd.exe` with the full argument but not a separate `appcmd.exe` event.
- No IIS configuration file write. Because IIS is not installed on this workstation, `appcmd.exe` failed (exit code `0x1`), so no `applicationHost.config` modification occurred and no Sysmon Event 11 for that file path exists.
- No `w3wp.exe` DLL image load — IIS worker processes are not running.
- No Sysmon Event 13 (registry set) — this method does not use the registry to register the module.

## Assessment

This is a good attempt-telemetry dataset. The full command line is preserved across both Security 4688 and Sysmon Event 1, and the parent-child relationship (`powershell.exe` → `cmd.exe` → intended `appcmd.exe`) is traceable. Because IIS is absent on the endpoint, the dataset represents the reconnaissance-and-attempt phase rather than a successful module install. For teams building detections against the attempt pattern (which is the realistic first-seen signal on workstations), this data is directly useful. Strengthening this dataset would require an IIS-enabled Windows Server endpoint where `appcmd.exe` completes successfully, producing `applicationHost.config` writes and subsequent `w3wp.exe` DLL loads.

## Detection Opportunities Present in This Data

1. **Security 4688 / Sysmon Event 1** — Process creation for `cmd.exe` with a command line containing `inetsrv\appcmd.exe install module`. Alert on `appcmd.exe install module` as a parent or grandchild of PowerShell or cmd.
2. **Security 4688** — Spawning of `appcmd.exe` by any process other than `inetmgr.exe` or legitimate IIS management tools is rare and high-confidence.
3. **Sysmon Event 1 rule tag** — The sysmon-modular annotation `technique_id=T1083` on the cmd.exe event can serve as a pre-built pivot point if your SIEM ingests rule tags.
4. **Parent-child anomaly** — `powershell.exe` spawning `cmd.exe` which in turn invokes IIS administration tools at SYSTEM integrity is not a normal workstation pattern and warrants investigation independent of the specific appcmd argument.
5. **Exit code 0x1 from appcmd** — A non-zero exit code combined with this command line indicates a failed attempt, which may warrant investigation even where IIS is absent (attacker probing for IIS presence).
