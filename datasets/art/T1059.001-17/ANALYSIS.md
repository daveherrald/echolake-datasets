# T1059.001-17: PowerShell — PowerShell Command Execution

## Technique Context

T1059.001 PowerShell is one of the most fundamental execution techniques in the Windows threat landscape. Attackers leverage PowerShell's built-in capabilities to execute commands, download payloads, perform reconnaissance, and maintain persistence while often evading traditional signature-based detection. The detection community focuses heavily on PowerShell telemetry because it provides rich visibility into attacker command lines, script blocks, and module usage. This technique is particularly concerning because PowerShell is a legitimate administrative tool, making it difficult to distinguish malicious usage from benign activity without proper context and behavioral analysis.

## What This Dataset Contains

This dataset captures a PowerShell execution chain demonstrating obfuscated command execution and invoke-expression (IEX) usage. The attack flow begins with a parent PowerShell process (PID 21224) that spawns whoami.exe for system discovery, then launches cmd.exe which in turn executes another PowerShell process (PID 38384) with a base64-encoded command.

The Security event logs show the complete process chain with command lines:
- `powershell.exe` (initial test framework process)
- `"C:\Windows\system32\whoami.exe"` (system discovery)
- `"cmd.exe" /c powershell.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==`

The PowerShell events reveal the deobfuscated technique execution. The base64 command decodes to: `& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")`. This demonstrates string concatenation obfuscation to build "Write-Host 'Hello, from PowerShell!'" and format string obfuscation to construct "iex" (Invoke-Expression alias).

The PowerShell Operational log captures script block 4104 events showing the obfuscated command construction and subsequent 4103 command invocation events for Get-Command, Invoke-Expression, and Write-Host with their parameters.

Sysmon provides detailed process creation events (EID 1) for whoami.exe, cmd.exe, and the second PowerShell process, along with process access events (EID 10) showing PowerShell accessing child processes with full access rights (0x1FFFFF). Multiple DLL load events (EID 7) capture .NET runtime initialization and Windows Defender integration.

## What This Dataset Does Not Contain

The dataset lacks certain expected PowerShell artifacts. Most PowerShell script block events contain only boilerplate error handling code (`Set-StrictMode`, `$_.PSMessageDetails`, etc.) rather than the actual technique payload, though the critical obfuscated command is captured. The dataset doesn't show any file system artifacts beyond PowerShell profile data creation, network connections, or registry modifications that might accompany more sophisticated PowerShell attacks. 

Windows Defender appears active (evidenced by MpOAV.dll and MpClient.dll loading), but doesn't block this technique since it's relatively benign command execution. The Sysmon ProcessCreate filter configuration means some intermediate processes might not be captured if they don't match the include patterns, though the key processes (PowerShell, cmd.exe, whoami.exe) are all present.

## Assessment

This dataset provides excellent telemetry for detecting obfuscated PowerShell execution patterns. The combination of Security 4688 events with full command-line logging, PowerShell 4103/4104 events, and Sysmon process creation provides comprehensive coverage of the attack chain. The base64-encoded parameter combined with string concatenation and format string obfuscation represents common real-world evasion techniques that detection engineers encounter regularly.

The data quality is high for building behavioral detections around PowerShell obfuscation patterns, invoke-expression usage, and suspicious process chains. The presence of both the encoded command line and the decoded script blocks allows for detection rule development at multiple stages of the attack lifecycle.

## Detection Opportunities Present in This Data

1. **Base64-encoded PowerShell execution** - Security 4688 events show `powershell.exe -e` with base64 parameter, a high-fidelity indicator of suspicious activity

2. **String concatenation obfuscation** - PowerShell script block 4104 events capture `"Wr"+"it"+"e-H"+"ost"` pattern indicating deliberate obfuscation attempts

3. **Format string obfuscation for command construction** - Script block shows `('ie{0}' -f 'x')` pattern used to build "iex" string dynamically

4. **Invoke-Expression usage** - PowerShell 4103 command invocation events show Invoke-Expression cmdlet execution with suspicious parameters

5. **PowerShell spawning system utilities** - Process chain shows PowerShell creating whoami.exe for system discovery activities

6. **Indirect PowerShell execution via cmd.exe** - Process relationship shows PowerShell -> cmd.exe -> PowerShell chain often used to evade detection

7. **PowerShell process access with full rights** - Sysmon 10 events show PowerShell accessing child processes with 0x1FFFFF permissions, indicating potential process manipulation

8. **Multiple PowerShell processes with different integrity contexts** - Process creation pattern suggests layered execution commonly used in attack scenarios
