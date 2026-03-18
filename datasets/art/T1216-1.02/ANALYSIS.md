# T1216-1: System Script Proxy Execution — SyncAppvPublishingServer Signed Script PowerShell Command Execution

## Technique Context

T1216 covers adversary abuse of legitimate, Microsoft-signed system scripts to proxy the execution of attacker-controlled commands. The specific vehicle here is `SyncAppvPublishingServer.vbs`, a VBScript shipped with Windows as part of the App-V (Application Virtualization) infrastructure. When called with a specially crafted argument string, this script passes the argument directly into a PowerShell invocation, effectively allowing arbitrary PowerShell execution through a trusted, signed script that many application allowlisting policies will permit.

The attack chain is indirect by design: rather than invoking PowerShell directly, an attacker calls `cmd.exe` with `SyncAppvPublishingServer.vbs` and embeds the payload in the argument. The VBScript engine (`wscript.exe`) then spawns PowerShell to fulfill the request. This indirection obscures the intent at the command-line level and leverages the script's legitimate provenance.

This test executes with `NT AUTHORITY\SYSTEM` privileges — a realistic post-exploitation scenario where an attacker already holds elevated access and is attempting to execute additional payloads while avoiding detection by endpoint controls focused on unsigned binaries.

## What This Dataset Contains

The dataset covers 4 seconds of execution (2026-03-17T16:42:57Z–16:43:01Z) and contains 168 total events across three channels: 120 PowerShell events (114 EID 4104 script block records, 6 EID 4103 module/pipeline records), 7 Security events (all EID 4688 process creation), and 41 Sysmon events (27 EID 7 image loads, 6 EID 1 process creations, 4 EID 10 process access, 2 EID 17 named pipe creates, 2 EID 11 file creates).

Sysmon EID 1 captures the key execution chain. The test framework invokes the technique from a parent `powershell` process running as SYSTEM. Two cmd.exe invocations appear in the captured sample: the attack invocation reads `"cmd.exe" /c C:\windows\system32\SyncAppvPublishingServer.vbs "\n;Start-Process calc"` — the newline-semicolon sequence is the parsing trick that causes the VBS script to interpret `Start-Process calc` as a PowerShell command to execute. A second cmd.exe invocation with an empty command line appears as part of test framework cleanup. Both are tagged by Sysmon's rules with `technique_id=T1059.003,technique_name=Windows Command Shell`.

The `whoami.exe` invocations (tagged T1033, System Owner/User Discovery) are Sysmon-visible pre- and post-test execution steps performed by the ART test framework to record the privilege context.

PowerShell EID 4103 records the test framework-level module calls including `Set-ExecutionPolicy Bypass -Scope Process -Force` and a `Write-Host "DONE"` after successful execution. The bulk of the 114 EID 4104 records are low-content boilerplate script blocks from the PowerShell error-handling framework (`Set-StrictMode`, `PSMessageDetails` closures), which are a normal artifact of any interactive PowerShell session and are present in both defended and undefended captures.

Sysmon EID 7 (image loaded) records show DLL loads into the process chain, including scripting engine components consistent with `wscript.exe` loading `vbscript.dll` and `wshom.ocx` as part of VBScript execution.

Compared to the defended dataset (sysmon: 58, security: 18, powershell: 48), this undefended capture contains fewer events overall (sysmon: 41, security: 7, powershell: 120). The security channel shows notably fewer 4688 events (7 vs. 18), suggesting that in the defended run additional process activity was generated — possibly by Defender scanning processes or by the test executing multiple times or cleanup steps generating more observable process spawns. The PowerShell channel is larger here (120 vs. 48) because more script block fragments are captured without interference.

## What This Dataset Does Not Contain

The `wscript.exe` process that actually executes the VBScript is not captured as a Sysmon EID 1 event in this dataset. The sysmon-modular configuration used in this environment operates in include mode and only captures process creation events that match pre-defined suspicious process patterns; `wscript.exe` launching from `cmd.exe` did not match a rule that generated a capture in the sample set. The spawned `powershell.exe` that runs the actual payload (with arguments like `-NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned`) is also not present as a Sysmon EID 1 in the samples, though it would be visible in the full event stream.

The Security channel EID 4688 events are present but their Message fields do not contain command-line detail in the samples as extracted — full command-line auditing output is available in the defended dataset analysis but the undefended security events here show process creation without the command-line field populated in the sample extraction.

There are no network connection events (Sysmon EID 3), registry modification events (EID 13), or DNS query events (EID 22) in this dataset. The payload (`Start-Process calc`) does not require network access. No file write activity attributable to the technique payload is present.

## Assessment

This dataset successfully captures the defining observable of the technique: `cmd.exe` invoking `SyncAppvPublishingServer.vbs` with the payload embedded in the argument string using the `\n;` delimiter. The Sysmon EID 1 record for that cmd.exe invocation is the single most important event in this dataset, and it is present.

The dataset is compact — 4 seconds, 168 events — and the technique-relevant signal is concentrated in a small number of events. The 120 PowerShell events are predominantly boilerplate from the PowerShell engine's error-handling internals and represent expected background volume for any SYSTEM-context PowerShell session. Compared to the defended variant, this capture provides a cleaner view of what a fully-executed technique looks like without Defender's process-scanning overhead adding events.

The absence of `wscript.exe` and the spawned hidden PowerShell process in the Sysmon EID 1 samples is a meaningful gap. Analysts working with this dataset should expect the full wscript.exe and final PowerShell process creation records to exist in the raw event stream beyond what is represented in the 20-event Sysmon sample.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — cmd.exe argument pattern:** The command line `"cmd.exe" /c C:\windows\system32\SyncAppvPublishingServer.vbs "\n;Start-Process calc"` contains the specific pattern of `SyncAppvPublishingServer.vbs` appearing as a cmd.exe argument combined with a semicolon-delimited PowerShell payload. The `\n;` sequence preceding a PowerShell command in this context is characteristic of this specific bypass technique.

**Parent-child relationship:** `powershell.exe` (running as SYSTEM) → `cmd.exe` → (`wscript.exe`) → `powershell.exe` is the expected process ancestry for this technique. The intermediate cmd.exe stage invoking a `.vbs` file with PowerShell-syntax arguments is unusual in normal enterprise activity.

**PowerShell EID 4103 — execution policy bypass:** The `Set-ExecutionPolicy Bypass -Scope Process -Force` script block, combined with a subsequent SYSTEM-context `Write-Host "DONE"`, provides process-scoped context that the session is operating under a forced execution policy bypass.

**Sysmon EID 17 — named pipe:** The PSHost named pipe created by the SYSTEM PowerShell process is a reliable indicator of an interactive or script-hosting PowerShell process running under SYSTEM context on a workstation, which is itself anomalous outside of maintenance windows.
