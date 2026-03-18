# T1216.001-1: System Script Proxy Execution: PubPrn — PubPrn.vbs Signed Script Bypass

## Technique Context

T1216.001 covers the abuse of `PubPrn.vbs`, a Microsoft-signed Visual Basic Script located in `C:\Windows\System32\Printing_Admin_Scripts\en-US\PubPrn.vbs`. This script was originally designed to publish printers to Active Directory. Its abuse stems from a quirk in how it processes its second argument: when called with a `script:` protocol handler URI in place of a printer server path, the script fetches and executes the content at that URL using the Windows Script Component (WSC) mechanism.

The technique is particularly interesting from a detection standpoint because it involves a Microsoft-signed script that can reach out to a remote URL and execute arbitrary script content, all through the legitimately installed `cscript.exe` or `wscript.exe` binary. This makes it effective against allowlisting controls that trust Microsoft-signed files.

In this test, the execution runs as `NT AUTHORITY\SYSTEM` on a domain workstation (`ACME-WS06.acme.local`) with Windows Defender disabled, so the technique executes without interference from real-time protection. The test produces one of the smaller event footprints in this T1216/T1218 series.

## What This Dataset Contains

The dataset spans roughly 2 seconds (2026-03-17T16:43:07Z–16:43:09Z) and contains 132 total events: 110 PowerShell events (104 EID 4104, 4 EID 4103, 2 EID 4100 engine lifecycle), 4 Security events (all EID 4688 process creation), and 18 Sysmon events (9 EID 7 image loads, 3 EID 1 process creations, 3 EID 10 process access, 1 EID 17 named pipe, 1 EID 8 CreateRemoteThread, 1 EID 11 file create).

The most significant event in this dataset is Sysmon EID 8 (CreateRemoteThread), which records an injection-like thread creation from `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 17716) into an `<unknown process>` target. This event carries the Sysmon rule tag `technique_id=T1055,technique_name=Process Injection`, and the source address `0x00007FF7818C0570` in a module identified as `-` (no named module). This is likely the ATH (Atomic Test Test framework) mechanism used by this test variant to invoke the CHM/PubPrn functionality in-process, rather than a conventional out-of-process spawn.

Sysmon EID 1 captures two `whoami.exe` invocations (tagged T1033, System Owner/User Discovery) running as SYSTEM under a PowerShell parent — these are the pre- and post-technique identity checks performed by the ART test framework.

The 4 Security EID 4688 events capture process creation activity at the OS audit level, but command-line details are not present in the extracted samples.

PowerShell EID 4100 (engine start/stop) events are present — these 2 events record the PowerShell engine lifecycle and provide timestamp anchors for when the PowerShell session that ran the technique started and completed. EID 4103 records include the `Set-ExecutionPolicy Bypass -Scope Process -Force` test framework setup step.

Compared to the defended dataset (sysmon: 25, security: 9, powershell: 41), the undefended capture shows substantially more events across all channels (sysmon: 18, security: 4, powershell: 110 vs. defended values). The defended run shows higher Sysmon and Security counts, suggesting that with Defender enabled additional scanning or remediation processes generate observable activity. The PowerShell channel is much larger undefended (110 vs. 41), capturing the full scope of the scripting session without truncation or interference.

## What This Dataset Does Not Contain

The dataset does not contain a Sysmon EID 1 process creation event for the actual PubPrn.vbs invocation itself (i.e., `cscript.exe` or `wscript.exe` launching `PubPrn.vbs`). The technique in this test variant appears to use the ATH framework's in-process invocation method rather than spawning an explicit child process, which explains the CreateRemoteThread event instead of a conventional process creation chain.

No network connection events (Sysmon EID 3) are present in this dataset. In a real-world use of this technique, a network connection would be expected if the `script:` URI points to a remote host — the absence here may reflect the test using a local payload or the network event falling outside the sample window.

No file creation events attributed to the PubPrn payload execution are present. There are no registry events (EID 13) or DNS query events (EID 22).

## Assessment

This dataset captures the technique executing under ideal conditions (Defender disabled, SYSTEM privileges), but the event footprint is sparse relative to what a full out-of-process PubPrn.vbs invocation would produce. The presence of the Sysmon EID 8 CreateRemoteThread event is the most forensically interesting artifact, as it records the ATH framework's injection of the technique execution into a target process — a pattern that itself could be used as a detection anchor in real environments.

The 110 PowerShell events are overwhelmingly boilerplate error-handling script blocks from the PowerShell engine internals, with the meaningful content limited to the execution policy bypass and cleanup commands. The core technique execution — the PubPrn.vbs abuse — is not directly visible in the PowerShell script block log because it executes through the WSC scripting pathway rather than PowerShell's engine.

Compared to the defended dataset, this capture offers a cleaner baseline of what the technique looks like without Defender's overhead, and the CreateRemoteThread event provides a detection-relevant artifact absent from some other T1216 test captures.

## Detection Opportunities Present in This Data

**Sysmon EID 8 — CreateRemoteThread from PowerShell:** A PowerShell process (SYSTEM context) creating a remote thread in another process with an unresolvable start module (`-`) is anomalous. This pattern — particularly from a PowerShell process running as SYSTEM on a workstation — warrants investigation regardless of the specific technique being employed.

**PowerShell EID 4100 engine lifecycle combined with SYSTEM context:** EID 4100 records the PowerShell engine starting and stopping. A SYSTEM-context PowerShell session on a domain workstation, bookended by EID 4100 events and containing only boilerplate script blocks plus a `Set-ExecutionPolicy Bypass` command, is characteristic of automated technique execution (either by an attacker or a tool like ART) rather than interactive administrative use.

**Security EID 4688 — process ancestry:** The combination of `NT AUTHORITY\SYSTEM` account name with a PowerShell parent process on a domain workstation during business hours is a baseline detection opportunity. While SYSTEM processes are common, the specific parent-child chain associated with this technique (PowerShell → scripting engine → child) appears in the Security channel.

**Sysmon EID 17 — PSHost named pipe under SYSTEM:** A named pipe with the pattern `\PSHost.*powershell` created by a SYSTEM-context process is a reliable indicator of a PowerShell hosting session that warrants scrutiny on workstation endpoints.
