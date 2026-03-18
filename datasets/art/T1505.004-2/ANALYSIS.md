# T1505.004-2: IIS Components — Install IIS Module using PowerShell Cmdlet New-WebGlobalModule

## Technique Context

T1505.004 (IIS Components) covers adversary use of IIS extensibility to achieve persistent server-side execution. This test uses the `WebAdministration` PowerShell module's `New-WebGlobalModule` cmdlet rather than the command-line `appcmd.exe` tool, representing a more programmatic, operator-friendly approach that some adversaries prefer because it avoids spawning a separate IIS administration binary. The net effect is identical: a native IIS module DLL is registered so it loads into every worker process on each web request. Detection focus should include both `appcmd.exe` and PowerShell WebAdministration cmdlet invocations.

## What This Dataset Contains

The test calls `New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll` inside a PowerShell script block. The evidence chain is:

**Security (Event ID 4688)** — Two process-create events are present:
- `whoami.exe` (ART test framework pre-check) spawned by `powershell.exe`
- A child `powershell.exe` process spawned by the test framework PowerShell, with the full command line: `"powershell.exe" & {New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll}`

**Sysmon (Event ID 1)** — Matching `ProcessCreate` events:
- `whoami.exe` tagged `technique_id=T1033`
- The child `powershell.exe` tagged `technique_id=T1083` (the sysmon-modular rule matched PowerShell with the `%windir%\system32\inetsrv` path in the command line)

**PowerShell (Event ID 4104)** — Two script block logging events capture the actual technique payload:
- `& {New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll}`
- The inner block `{New-WebGlobalModule -Name DefaultDocumentModule_Atomic -Image %windir%\system32\inetsrv\defdoc.dll}`

These script block events are the highest-fidelity evidence in the dataset — they record the exact cmdlet invocation with named parameters.

**PowerShell (Event ID 4103)** — Module logging events are present but largely contain boilerplate (`Set-ExecutionPolicy`). The `New-WebGlobalModule` invocation itself is not separately captured in 4103 in this dataset.

## What This Dataset Does Not Contain

- No successful module registration. IIS is not installed on this workstation, so `New-WebGlobalModule` throws an exception rather than writing to `applicationHost.config`. There is no Sysmon Event 11 showing a configuration file write.
- No `w3wp.exe` DLL image load or IIS-related process activity.
- No Sysmon Event 13 (registry modification) — the WebAdministration method writes to IIS configuration rather than the registry.
- The PowerShell 4103 module logging does not emit a dedicated event for `New-WebGlobalModule`; rely on 4104 script block logging for cmdlet-level visibility.

## Assessment

The PowerShell script block capture (Event ID 4104) makes this the higher-fidelity of the two T1505.004 datasets for defenders who prioritize PowerShell-based detection. The full cmdlet name and parameters appear verbatim in the script block, making string-matching straightforward. The dataset correctly captures the attempt even though IIS is absent, reflecting realistic telemetry from a workstation where an attacker tests capabilities. An IIS-enabled server dataset would add successful configuration file writes and DLL loads, but for rule development against the execution phase this data is sufficient.

## Detection Opportunities Present in This Data

1. **PowerShell 4104 (script block logging)** — `New-WebGlobalModule` in any script block is a high-confidence indicator; legitimate IIS administration occurs in `inetmgr.exe` or dedicated automation scripts, not ART-style one-liner invocations.
2. **Security 4688 / Sysmon Event 1** — Child `powershell.exe` spawned with a command line referencing `inetsrv` from a SYSTEM-context parent PowerShell process. The `%windir%\system32\inetsrv` path in a PowerShell argument is an unusual workstation pattern.
3. **PowerShell 4103 `Set-ExecutionPolicy -Scope Process -Bypass`** combined with subsequent `inetsrv` references — the bypass-then-IIS-cmdlet sequence warrants correlation.
4. **Sysmon Event 1 with rule tag `technique_id=T1083`** on the child `powershell.exe` — usable as a triage pivot if rule tags are indexed.
5. **Parent-child pattern** — `powershell.exe` (SYSTEM, integrity level System) spawning a child `powershell.exe` that immediately references IIS paths is anomalous on domain workstations where IIS is not installed.
