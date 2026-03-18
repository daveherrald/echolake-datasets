# T1218.011-16: Rundll32 — Rundll32 execute payload by calling RouteTheCall

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows Rundll32.exe utility to execute malicious code. Rundll32 is designed to execute functions exported by DLLs, making it a common target for Living Off The Land Binary (LOLBin) abuse. The RouteTheCall export from zipfldr.dll is particularly interesting—it's a legitimate Windows Shell extension function that can be misused to execute arbitrary commands while appearing to originate from the trusted rundll32.exe process.

Detection engineers focus on unusual rundll32 command lines, unexpected DLL/function combinations, and parent-child process relationships that don't align with normal Windows operations. The RouteTheCall technique is less commonly observed than other rundll32 abuses, making it valuable for understanding how attackers leverage obscure Windows functionality.

## What This Dataset Contains

This dataset captures a successful execution of rundll32 calling the RouteTheCall function from zipfldr.dll to launch calc.exe. The key evidence includes:

**Process Creation Chain**: Security events show the process lineage: PowerShell (PID 34536) → PowerShell (PID 16796) → rundll32.exe (PID 30456). The rundll32 command line is `"C:\Windows\system32\rundll32.exe" zipfldr.dll,RouteTheCall '%%windir%%\System32\calc.exe'`.

**Sysmon Process Creation**: Two Sysmon EID 1 events capture the child processes - whoami.exe for system discovery and the rundll32 execution with the full command line showing the RouteTheCall invocation.

**PowerShell Script Blocks**: EID 4104 events capture the PowerShell command `& {rundll32.exe zipfldr.dll,RouteTheCall "'%windir%\System32\calc.exe'"}`, showing the technique being invoked from a PowerShell script context.

**Process Access Events**: Sysmon EID 10 events show PowerShell processes accessing child processes with full access rights (0x1FFFFF), indicating process monitoring or injection attempts during execution.

**DLL Loading**: Multiple Sysmon EID 7 events capture .NET runtime and PowerShell automation DLL loads, along with Windows Defender components being loaded into the PowerShell processes.

## What This Dataset Does Not Contain

**calc.exe Process Creation**: Neither Sysmon nor Security logs show calc.exe being created, despite the RouteTheCall function being designed to execute it. This suggests either the technique failed to launch the target executable or the sysmon-modular configuration filtered out calc.exe process creation events.

**Network Activity**: No Sysmon EID 3 events show network connections, which is expected since calc.exe doesn't typically generate network traffic.

**File System Changes**: Beyond PowerShell profile file creation, there are no file modification events showing calc.exe execution artifacts or temporary files that might be created during the process launch.

**Registry Modifications**: No Sysmon EID 12/13 events capture registry changes, indicating this technique doesn't rely on registry persistence or configuration changes.

## Assessment

This dataset provides excellent visibility into the rundll32 RouteTheCall technique from a process execution and command-line perspective. The Security channel's 4688 events with full command-line logging capture the critical detection artifacts, while PowerShell script block logging reveals the attack context. The Sysmon process creation events complement this with detailed process metadata and hashes.

However, the dataset's value is diminished by the apparent failure to capture the final payload execution (calc.exe). This could indicate the technique partially failed or that certain processes weren't deemed suspicious enough for the sysmon-modular include-mode filtering. For complete technique analysis, seeing the successful payload execution would strengthen the dataset.

The process access events (EID 10) provide valuable behavioral context, showing how PowerShell monitors child processes during execution, which could be useful for detecting similar automation frameworks.

## Detection Opportunities Present in This Data

1. **Rundll32 Command Line Pattern Detection**: Monitor for `rundll32.exe` with `zipfldr.dll,RouteTheCall` in Security EID 4688 events, particularly when the function parameter contains executable paths or suspicious commands.

2. **PowerShell Script Block Analysis**: Detect PowerShell EID 4104 events containing `rundll32` invocations with `RouteTheCall`, especially when combined with executable paths in the function parameters.

3. **Unusual Parent-Child Process Relationships**: Alert on rundll32.exe spawned by PowerShell processes, particularly when the rundll32 command line contains non-standard DLL exports like RouteTheCall.

4. **Process Access Behavior**: Monitor Sysmon EID 10 events where PowerShell processes open rundll32 with full access rights (0x1FFFFF), indicating potential process injection or monitoring activity.

5. **DLL/Export Combination Allowlisting**: Create detection rules for rundll32 invocations using zipfldr.dll with exports other than expected Windows Shell functionality.

6. **PowerShell Execution Policy Bypass Detection**: Correlate PowerShell EID 4103 `Set-ExecutionPolicy Bypass` events with subsequent rundll32 abuse to identify script-based attack chains.

7. **Command Line Obfuscation Detection**: Look for environment variable usage (`%windir%`) in rundll32 RouteTheCall parameters as a potential obfuscation or evasion technique.
