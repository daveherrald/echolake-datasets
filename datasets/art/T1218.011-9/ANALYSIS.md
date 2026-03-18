# T1218.011-9: Rundll32 — Launches an executable using Rundll32 and pcwutl.dll

## Technique Context

T1218.011 (Rundll32) is a defense evasion technique where attackers abuse the legitimate Windows rundll32.exe utility to execute malicious code. Rundll32.exe is designed to load and execute DLL functions, making it a powerful proxy execution tool. Attackers commonly use rundll32.exe to execute malicious DLLs, bypass application whitelisting, or launch processes in unexpected contexts.

This specific test demonstrates using rundll32.exe with pcwutl.dll's LaunchApplication function to execute notepad.exe. The pcwutl.dll (PC Wellness Utility) is a legitimate Windows component that includes functions for launching applications. The detection community focuses on monitoring unusual rundll32.exe command lines, especially those invoking uncommon DLL/function combinations, processes launched by rundll32.exe, and the parent-child relationships that rundll32.exe creates.

## What This Dataset Contains

This dataset captures a successful rundll32.exe execution chain with excellent telemetry coverage:

**Process Creation Chain (Security 4688 & Sysmon 1):**
- PowerShell → cmd.exe → rundll32.exe → notepad.exe
- Key command: `rundll32.exe pcwutl.dll,LaunchApplication C:\Windows\System32\notepad.exe`
- Full process lineage preserved with command lines and parent-child relationships

**Sysmon Process Creation Events:**
- EID 1 for whoami.exe: `"C:\Windows\system32\whoami.exe"` (reconnaissance)
- EID 1 for cmd.exe: `"cmd.exe" /c rundll32.exe pcwutl.dll,LaunchApplication %%windir%%\System32\notepad.exe`
- EID 1 for rundll32.exe: `rundll32.exe pcwutl.dll,LaunchApplication C:\Windows\System32\notepad.exe`

**Process Access Events (Sysmon 10):**
- PowerShell accessing whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- Shows PowerShell managing child processes during execution

**Image Load Events (Sysmon 7):**
- Multiple PowerShell .NET runtime loads (mscoree.dll, mscoreei.dll, clr.dll)
- Rundll32.exe loading urlmon.dll
- Notepad.exe loading urlmon.dll

The technique executed successfully with exit status 0x0 for all processes, demonstrating that Windows Defender did not block this particular rundll32.exe usage.

## What This Dataset Does Not Contain

**Missing DLL Load Evidence:** Sysmon did not capture pcwutl.dll being loaded by rundll32.exe, likely due to the sysmon-modular configuration's filtering rules not covering this specific legitimate DLL.

**No Network Activity:** The technique did not generate network connections, DNS queries, or other network-related telemetry.

**Limited File System Activity:** Only basic PowerShell profile file creation was captured (EID 11), with no evidence of the pcwutl.dll access or notepad.exe file operations.

**No Registry Activity:** The dataset contains no registry modifications, which is expected for this straightforward process execution technique.

## Assessment

This dataset provides strong telemetry for detecting T1218.011 rundll32.exe abuse. The Security 4688 events with command-line logging capture the complete attack sequence, while Sysmon 1 events provide additional process creation context with hashes and integrity levels. The preservation of the full process tree (PowerShell → cmd → rundll32 → notepad) is particularly valuable for detection engineering.

The process access events (Sysmon 10) add behavioral context showing how PowerShell manages the child processes. However, the absence of pcwutl.dll load events in Sysmon 7 represents a gap that could be addressed with broader image load monitoring.

For rundll32.exe detection, this dataset demonstrates both the command-line patterns and process relationships that defenders should monitor, making it highly useful for rule development and testing.

## Detection Opportunities Present in This Data

1. **Rundll32.exe Process Creation with Unusual DLL/Function**: Monitor Sysmon EID 1 and Security EID 4688 for rundll32.exe command lines containing `pcwutl.dll,LaunchApplication` or other uncommon DLL/function combinations.

2. **Rundll32.exe Parent Process Analysis**: Detect rundll32.exe spawned by cmd.exe or PowerShell, especially when the parent command line contains rundll32.exe execution parameters.

3. **Rundll32.exe Child Process Monitoring**: Alert on rundll32.exe creating unexpected child processes, particularly legitimate applications like notepad.exe in enterprise environments.

4. **Process Tree Correlation**: Correlate PowerShell → cmd.exe → rundll32.exe → application execution chains using ProcessGuid relationships in Sysmon events.

5. **Command Line Pattern Matching**: Monitor for cmd.exe command lines containing `rundll32.exe` followed by DLL names and function calls, especially with environment variable expansion patterns like `%%windir%%`.

6. **Process Access Behavior**: Detect PowerShell processes accessing rundll32.exe or its child processes with full access rights (0x1FFFFF), indicating process management or injection preparation.

7. **Legitimate Application Abuse**: Monitor for legitimate applications (notepad.exe, calc.exe, etc.) being launched by rundll32.exe in environments where this is unexpected.
