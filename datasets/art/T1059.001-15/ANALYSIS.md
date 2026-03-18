# T1059.001-15: PowerShell — ATHPowerShellCommandLineParameter -EncodedCommand parameter variations

## Technique Context

T1059.001 (PowerShell) is a critical execution technique where attackers leverage PowerShell's extensive capabilities to run malicious commands, scripts, and payloads. PowerShell's `-EncodedCommand` parameter is particularly valuable to attackers because it allows base64-encoded commands to be executed, helping evade basic string-based detections and command-line logging that might flag suspicious plaintext PowerShell operations.

The `-EncodedCommand` parameter (and its variations like `-e`, `-en`, `-enc`) accepts base64-encoded Unicode text, making it harder for defenders to immediately understand the payload's intent when reviewing process command lines. Attackers commonly use this technique for initial access payloads, lateral movement scripts, and persistence mechanisms. Detection engineers focus on identifying base64 patterns in PowerShell command lines, decoding suspicious content, and monitoring for PowerShell execution patterns that suggest encoded payload delivery.

## What This Dataset Contains

This dataset captures the execution of the Out-ATHPowerShellCommandLineParameter function with `-EncodedCommandParamVariation E` testing, which appears to test various forms of the `-EncodedCommand` parameter. The execution shows multiple PowerShell processes created in succession.

Security Event 4688 captures the primary PowerShell execution: `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}`. This reveals the test framework command that spawns the encoded command variations.

Sysmon captures detailed process creation chains showing PowerShell spawning whoami.exe (EID 1: `"C:\Windows\system32\whoami.exe"`) and additional PowerShell child processes. The PowerShell processes load standard .NET assemblies (mscoree.dll, clr.dll) and System.Management.Automation.ni.dll, indicating full PowerShell engine initialization.

PowerShell script block logging (EID 4104) contains the test framework code: `& {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}` and `{Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}`. However, most script blocks are PowerShell formatting engine boilerplate (`Set-StrictMode -Version 1`) rather than the actual encoded payloads being tested.

## What This Dataset Does Not Contain

The dataset notably lacks the actual `-EncodedCommand` parameter usage and base64-encoded payloads in the captured command lines. The test appears to use the Out-ATHPowerShellCommandLineParameter function internally, but the resulting encoded PowerShell executions with base64 parameters are not visible in the Security 4688 or Sysmon EID 1 events.

PowerShell script block logging doesn't capture the decoded content of any base64 payloads that may have been executed. The 4104 events primarily contain test framework boilerplate and PowerShell engine internals rather than the technique-specific encoded commands.

Network connections, file writes beyond PowerShell profile data, and registry modifications that might result from decoded payload execution are absent from this dataset. The technique testing appears to focus on process execution patterns rather than payload effects.

## Assessment

This dataset provides limited utility for developing detections specifically targeting the `-EncodedCommand` parameter technique. While it demonstrates PowerShell process creation patterns and engine initialization, it doesn't contain the core behavioral indicators that defenders need to detect encoded PowerShell attacks: base64 strings in command lines, suspicious decoded content, or the characteristic process spawning patterns of encoded payloads.

The Security 4688 events with command-line logging would be the primary detection source for this technique, but the visible command lines show the test framework rather than the actual `-EncodedCommand` usage. For stronger detection development, the dataset would need to capture actual PowerShell executions with visible `-e`, `-en`, `-enc`, or `-EncodedCommand` parameters followed by base64 strings.

The process access events (Sysmon EID 10) showing PowerShell accessing whoami.exe and other PowerShell processes indicate some payload execution occurred, but without the encoded command context, these behaviors could represent many different PowerShell activities.

## Detection Opportunities Present in This Data

1. **PowerShell Child Process Spawning** - Monitor for powershell.exe spawning whoami.exe or other discovery tools, particularly when the parent PowerShell process shows signs of automated execution.

2. **Rapid PowerShell Process Creation** - Detect multiple PowerShell processes created in quick succession (within seconds), which may indicate encoded payload testing or execution.

3. **PowerShell Engine Loading Patterns** - Monitor for System.Management.Automation.ni.dll loads combined with suspicious child process creation as an indicator of PowerShell payload execution.

4. **PowerShell Process Access Patterns** - Alert on PowerShell processes accessing recently spawned child processes with full access rights (0x1FFFFF), indicating potential process manipulation.

5. **PowerShell Test Test framework Detection** - Flag PowerShell executions containing "ATH" or "CommandLineParameter" strings, which indicate Atomic Red Team testing activity.

6. **Cross-Process PowerShell Communication** - Monitor for PowerShell processes accessing other PowerShell processes, which may indicate inter-process communication during encoded payload execution.

7. **PowerShell Profile Data Creation** - Track PowerShell profile data file creation combined with suspicious process spawning as a potential indicator of PowerShell-based attack tools.
