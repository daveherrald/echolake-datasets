# T1218.011-2: Rundll32 — Rundll32 execute VBscript command

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to proxy execution of malicious code. Rundll32 is designed to execute functions from DLLs, but attackers have discovered creative ways to leverage it for script execution, including VBScript and JScript payloads. This particular test demonstrates using rundll32 with a VBScript protocol handler to execute arbitrary commands while appearing as legitimate system activity.

The detection community focuses on unusual rundll32 command lines, particularly those invoking script engines (vbscript:, javascript:, etc.), loading from unusual paths, or executing with suspicious parent processes. This technique is valuable to attackers because rundll32.exe is a signed Microsoft binary that's commonly present on systems, making it an effective LOLBin for defense evasion.

## What This Dataset Contains

This dataset captures a rundll32 VBScript execution attempt that was blocked by Windows Defender. The core evidence is in Security event 4688, showing the command line: `"cmd.exe" /c rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)`. 

The process chain shows:
- PowerShell (PID 18112) as the parent process
- cmd.exe (PID 19056) launched to execute the rundll32 command
- The cmd.exe process exits with status 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution

Sysmon captures the PowerShell process initialization (EID 1) for whoami.exe execution that occurs before the blocked rundll32 attempt, along with extensive image loading events (EID 7) showing .NET runtime and Windows Defender components being loaded. A CreateRemoteThread event (EID 8) shows PowerShell attempting to inject into an unknown process (PID 19056), which corresponds to the blocked cmd.exe process.

The PowerShell channel contains only framework boilerplate (Set-ExecutionPolicy Bypass commands and Set-StrictMode scriptblocks) without capturing the actual rundll32 invocation script.

## What This Dataset Does Not Contain

This dataset lacks the successful execution telemetry because Windows Defender blocked the rundll32 attempt before completion. There are no Sysmon ProcessCreate events for rundll32.exe itself, no DLL loading events for mshtml.dll or vbscript-related components, and no evidence of calc.exe being spawned. The sysmon-modular config's include-mode filtering also means we don't see the cmd.exe ProcessCreate event in Sysmon, though Security 4688 captures it.

Since the technique was blocked, there's no network activity, file system modifications beyond PowerShell profile updates, or registry changes that would occur during successful VBScript execution. The dataset also doesn't contain any Application or System log events that might show Defender's blocking activity in detail.

## Assessment

This dataset provides excellent evidence of attempted rundll32 abuse with VBScript, even though the execution was blocked. The Security audit logs capture the full command line, showing the exact VBScript payload structure that detection engineers need to identify this technique. The combination of process creation events, exit codes, and Sysmon's process access/injection events creates a comprehensive picture of the attack attempt and its prevention.

The blocked execution actually enhances the dataset's value for detection engineering, as it shows how this technique appears when defensive tools are active. The clear process chain from PowerShell to cmd.exe to the intended rundll32 execution provides multiple detection points for building robust rules.

## Detection Opportunities Present in This Data

1. **Rundll32 VBScript Command Line Detection**: Monitor Security 4688 events for cmd.exe or PowerShell spawning rundll32 with "vbscript:" in the command line, particularly with mshtml references

2. **Suspicious Process Exit Codes**: Alert on cmd.exe processes terminating with 0xC0000022 (STATUS_ACCESS_DENIED) when the command line contains rundll32 and script protocol handlers

3. **PowerShell to CMD Chain**: Detect PowerShell spawning cmd.exe with rundll32 commands containing script execution patterns like "CreateObject" and "WScript.Shell"

4. **Process Injection from PowerShell**: Monitor Sysmon EID 8 (CreateRemoteThread) where PowerShell injects into short-lived or unknown processes, especially when correlated with blocked executions

5. **VBScript Protocol Handler Abuse**: Create signatures for command lines containing "vbscript:" followed by DLL references and script execution functions

6. **Rundll32 with HTML Application Functions**: Alert on rundll32 command lines referencing "RunHTMLApplication" combined with script object creation patterns
