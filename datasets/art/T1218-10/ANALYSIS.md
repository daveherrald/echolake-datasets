# T1218-10: System Binary Proxy Execution — Lolbin Gpscript logon option

## Technique Context

T1218 System Binary Proxy Execution encompasses adversaries' use of legitimate Windows binaries to execute malicious payloads, bypassing application controls and security monitoring that focuses on suspicious executables. The gpscript.exe technique (T1218-10) specifically leverages the Group Policy Client-Side Extensions Script Processing binary with the `/logon` parameter to execute arbitrary commands. This technique is particularly valuable to attackers because gpscript.exe is a signed Microsoft binary that typically executes during normal system operations, making malicious use harder to distinguish from legitimate activity. The detection community focuses on unusual command-line arguments, unexpected parent-child process relationships, and gpscript.exe execution outside of standard Group Policy processing contexts.

## What This Dataset Contains

This dataset captures a successful execution of the gpscript.exe Living off the Land Binary (LOLBin) technique. The key evidence is in Security event 4688, which shows the process chain: PowerShell spawns cmd.exe with command line `"cmd.exe" /c Gpscript /logon`, and cmd.exe subsequently spawns gpscript.exe with command line `Gpscript /logon`. Sysmon Event ID 1 captures the cmd.exe process creation with ProcessId 45004 and the complete command line showing the gpscript invocation. The parent process is PowerShell (PID 6992) executing under NT AUTHORITY\SYSTEM context.

The dataset also contains extensive PowerShell telemetry showing Set-ExecutionPolicy bypass operations and typical test framework boilerplate, plus a whoami.exe execution (captured in both Security 4688 and Sysmon Event ID 1) that appears to be related reconnaissance. Sysmon Event ID 10 shows PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating the test framework monitoring child process execution.

## What This Dataset Does Not Contain

The dataset does not contain the actual payload executed by gpscript.exe or evidence of what the binary accomplished after execution. While gpscript.exe appears in the Security 4688 process creation event, there is no corresponding Sysmon Event ID 1 for gpscript.exe, likely because the sysmon-modular configuration's include-mode filtering does not classify gpscript.exe as a suspicious binary requiring detailed monitoring. The dataset also lacks file creation events, registry modifications, or network connections that might result from gpscript.exe execution, suggesting either the technique executed a minimal payload or additional activity was filtered out by the monitoring configuration.

## Assessment

This dataset provides solid evidence for detecting the gpscript.exe LOLBin technique through process creation telemetry. The Security channel's command-line logging captures the complete execution chain clearly, while Sysmon provides additional process metadata and parent-child relationships. The combination of Security 4688 events and Sysmon Event ID 1 data gives detection engineers multiple angles to identify this technique. However, the dataset's utility is somewhat limited by the lack of post-execution activity telemetry, which would help analysts understand the full impact of successful gpscript.exe abuse. The presence of PowerShell in the execution chain also provides additional detection opportunities through PowerShell operational logs.

## Detection Opportunities Present in This Data

1. Security Event ID 4688 process creation monitoring for gpscript.exe with unusual command-line arguments, particularly `/logon` parameter usage outside of standard Group Policy processing contexts

2. Sysmon Event ID 1 process creation detection for cmd.exe spawning gpscript.exe, focusing on parent processes that are not typical Group Policy infrastructure components

3. Command-line analysis detecting the specific pattern `Gpscript /logon` or variations, especially when executed via cmd.exe /c wrapper commands

4. Process tree analysis identifying PowerShell → cmd.exe → gpscript.exe execution chains that deviate from normal administrative workflows

5. Parent process validation ensuring gpscript.exe execution originates from legitimate Group Policy services rather than user-initiated processes or shells

6. Sysmon Event ID 10 process access monitoring for unusual processes opening handles to gpscript.exe, indicating potential process injection or monitoring by malicious code

7. Temporal correlation between gpscript.exe execution and reconnaissance commands like whoami.exe to identify broader attack patterns
