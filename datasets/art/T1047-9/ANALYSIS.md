# T1047-9: Windows Management Instrumentation — WMI Execute rundll32

## Technique Context

T1047 Windows Management Instrumentation is a critical lateral movement and execution technique used by attackers to execute commands on local or remote systems through WMI. This specific test (T1047-9) demonstrates using WMI to execute rundll32.exe with a malicious DLL, combining two common Living off the Land Binary (LOLBin) techniques. Attackers frequently use this approach because WMI process creation can appear legitimate and may bypass some security controls that focus on direct process execution. The detection community typically focuses on WMI process creation events, command-line analysis of wmic.exe usage, and monitoring for suspicious rundll32.exe invocations with unusual DLL paths or entry points.

## What This Dataset Contains

The dataset captures a complete WMI-based execution attempt that was blocked by Windows Defender. The key evidence includes:

**Security Event 4688** showing the WMI command execution: `"cmd.exe" /c wmic /node:127.0.0.1 process call create "rundll32.exe \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\calc.dll\" StartW"`

**Security Event 4689** showing the cmd.exe process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Events** provide rich process telemetry including:
- Process creation (EID 1) for whoami.exe execution by PowerShell
- Process access (EID 10) showing PowerShell accessing the whoami process
- CreateRemoteThread (EID 8) detecting PowerShell injecting into an unknown target process
- Multiple image load events (EID 7) showing .NET runtime and Windows Defender components
- Named pipe creation (EID 17) from PowerShell processes

**PowerShell Events** contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific content.

## What This Dataset Does Not Contain

The dataset lacks the actual WMI execution telemetry because Windows Defender blocked the technique before completion. Missing elements include:
- No WMI-Activity/Operational events showing the WMI process creation call
- No rundll32.exe process creation events (blocked by Defender)
- No calc.dll loading or execution events
- No Sysmon ProcessCreate events for wmic.exe or rundll32.exe (the sysmon-modular config uses include-mode filtering, but these processes would normally be captured)
- No network activity from the localhost WMI connection
- The CreateRemoteThread event shows an unknown target process, suggesting the injection attempt was also partially blocked

## Assessment

This dataset provides excellent evidence of a WMI-based execution attempt and demonstrates how modern endpoint protection affects telemetry collection. The Security channel events clearly show the attack vector (wmic process call create with rundll32), while the access denied exit code provides definitive evidence of the block. The Sysmon events capture related PowerShell activity and process injection attempts, giving defenders visibility into the broader attack context even when the primary technique is blocked. However, the lack of successful execution means defenders cannot study the complete attack chain or develop detections for the post-exploitation phase.

## Detection Opportunities Present in This Data

1. **WMI Command Line Execution Patterns** - Security 4688 events showing `wmic` with `/node:` parameters and `process call create` syntax, especially with rundll32.exe as the target process

2. **Rundll32 with Suspicious DLL Paths** - Command lines containing rundll32.exe pointing to non-system locations like `\AtomicRedTeam\` or `\ExternalPayloads\` directories

3. **Access Denied Exit Codes** - Security 4689 events with exit status `0xC0000022` indicating blocked execution attempts, particularly from cmd.exe processes spawned by PowerShell

4. **PowerShell Process Injection Patterns** - Sysmon EID 8 CreateRemoteThread events where PowerShell is the source process, combined with EID 10 process access events

5. **Localhost WMI Node Specification** - Command lines using `/node:127.0.0.1` or `/node:localhost` which may indicate local WMI abuse for defense evasion

6. **PowerShell Privilege Token Adjustments** - Security 4703 events showing PowerShell processes enabling multiple high-privilege tokens including SeBackupPrivilege and SeLoadDriverPrivilege
