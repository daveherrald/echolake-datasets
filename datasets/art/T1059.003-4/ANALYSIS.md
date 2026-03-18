# T1059.003-4: Windows Command Shell — Simulate BlackByte Ransomware Print Bombing

## Technique Context

T1059.003 (Windows Command Shell) is a fundamental execution technique where adversaries use cmd.exe to execute commands, scripts, and binaries. The "print bombing" variant simulates a technique used by BlackByte ransomware, which creates numerous print jobs to overwhelm system resources and potentially disrupt operations. This technique serves both as a denial-of-service mechanism and as a distraction during the encryption phase of ransomware operations. Detection engineers focus on monitoring for unusual patterns of process creation, especially bulk spawning of applications like WordPad with print-related command line arguments, and resource exhaustion indicators.

## What This Dataset Contains

This dataset captures a comprehensive print bombing attack executed through a PowerShell to cmd.exe chain. The attack begins with PowerShell execution policy bypass (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) followed by the core command: `cmd /c "for /l %x in (1,1,75) do start wordpad.exe /p C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059_003note.txt"`.

The Security log shows the complete process chain: PowerShell (PID 13036) → PowerShell (PID 12664) → cmd.exe (PID 14304) → 75 wordpad.exe processes. Each WordPad instance launched with the `/p` print flag and targeting the same text file. Sysmon captures only two process creation events (EID 1) for whoami.exe and the PowerShell/cmd.exe chain due to include-mode filtering, but provides extensive image loading telemetry (EID 7) showing Windows Defender's MpOAV.dll and AMSI integration across the WordPad processes. The PowerShell channel contains primarily test framework boilerplate with the actual attack command visible in Security 4688 events.

## What This Dataset Does Not Contain

The dataset lacks Sysmon process creation events for the 75 WordPad instances due to the sysmon-modular include-mode filtering that only captures known-suspicious process patterns. There are no network connections, file modifications, or registry changes associated with this technique since it's purely a resource exhaustion attack. The dataset also doesn't capture the actual print spooler interactions or printer queue status that would show the print jobs being created, nor any system performance metrics that would indicate resource exhaustion. Windows Defender was active but did not block this technique since it uses legitimate system functionality in an abusive manner.

## Assessment

This dataset provides strong coverage for detecting print bombing attacks through Security 4688 process creation events, which capture the complete attack chain with full command lines. The PowerShell script block logging (EID 4104) captures the attack command execution, though most events are test framework-related boilerplate. Sysmon's image loading events (EID 7) provide valuable context about Windows Defender's interaction with the spawned processes. However, the lack of Sysmon process creation events for the bulk WordPad spawning limits visibility into the full scope of the attack. The dataset would be stronger with performance counters, print spooler logs, or custom logging for bulk process creation patterns.

## Detection Opportunities Present in This Data

1. **Bulk Process Creation Detection** - Monitor Security 4688 events for rapid creation of multiple identical processes (75 wordpad.exe instances) within short time windows, especially with print-related command line arguments like `/p`.

2. **Command Loop Pattern Detection** - Alert on cmd.exe processes with `for /l` loop constructs combined with `start` commands, particularly when spawning applications with print functionality.

3. **Print-Specific Application Abuse** - Detect unusual patterns of WordPad, Notepad, or other document viewers launched with print flags (`/p`, `/pt`) targeting the same file repeatedly.

4. **PowerShell Execution Policy Bypass** - Monitor PowerShell 4103 command invocation events for `Set-ExecutionPolicy` with `Bypass` parameter, especially when followed by suspicious script execution.

5. **Resource Exhaustion Precursors** - Create rules for processes spawning excessive child processes (parent process creating 50+ children) as an early indicator of resource exhaustion attacks.

6. **AMSI Integration Monitoring** - Track unusual patterns of AMSI.dll loading across multiple processes of the same type, which may indicate scripted automation of legitimate applications for malicious purposes.
