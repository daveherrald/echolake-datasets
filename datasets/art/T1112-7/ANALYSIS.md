# T1112-7: Modify Registry — Change Powershell Execution Policy to Bypass

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where attackers modify Windows registry keys to alter system behavior, disable security controls, or maintain persistence. PowerShell execution policy modification is a particularly common application of this technique. The execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts. By setting it to "Bypass," attackers can execute unsigned scripts and bypass script execution restrictions that might otherwise prevent malicious PowerShell activity.

The detection community focuses heavily on registry modifications to security-relevant keys, particularly those affecting PowerShell execution policy, Windows Defender settings, and other security controls. These modifications often occur early in attack chains as adversaries prepare the environment for subsequent malicious activities. PowerShell execution policy changes are especially significant because they frequently precede script-based attacks, credential harvesting, or lateral movement activities.

## What This Dataset Contains

This dataset captures a straightforward PowerShell execution policy modification from "Restricted" to "Bypass" at the LocalMachine scope. The core evidence appears in Sysmon Event ID 13 (Registry value set):

`HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy` set to value `Bypass`

The attack sequence shows in Security Event ID 4688 process creation events with the command line `"powershell.exe" & {Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine}`. PowerShell logging captured the actual cmdlet execution in Event ID 4103, showing the `Set-ExecutionPolicy` command with parameters `ExecutionPolicy="Bypass"` and `Scope="LocalMachine"`.

The Sysmon data includes multiple PowerShell process creations (Event ID 1), extensive DLL loading events (Event ID 7) showing .NET framework initialization, named pipe creation (Event ID 17), and process access events (Event ID 10) as PowerShell spawns child processes including whoami.exe for system discovery.

## What This Dataset Does Not Contain

The dataset lacks several elements that would make it more comprehensive for detection engineering. There are no registry read events prior to the modification, so we cannot observe reconnaissance of the current execution policy state. The Sysmon configuration's include-mode filtering means we don't see all process creation events—only those matching known suspicious patterns. 

Notably absent are Windows Defender alerts or blocking actions despite real-time protection being enabled. This suggests the technique executed successfully without AV interference. The PowerShell channel contains mostly infrastructure events (error handlers, module loading) rather than detailed script content, limiting visibility into the full execution context. There are also no network events or subsequent script execution events that would show the practical application of the bypassed execution policy.

## Assessment

This dataset provides excellent core evidence for detecting PowerShell execution policy modifications. The registry modification event (Sysmon EID 13) is the gold standard detection point for this technique, containing the exact registry key, value, and process responsible. The command-line logging from Security EID 4688 and PowerShell EID 4103 provides strong supplementary evidence with full parameter visibility.

However, the dataset's utility is somewhat limited by the lack of follow-on activity that would demonstrate why execution policy bypass matters in a real attack scenario. The technique succeeds completely, making this good data for detecting successful policy modifications but less useful for understanding attack progression or developing behavioral detections around policy abuse.

## Detection Opportunities Present in This Data

1. **Registry Modification Detection**: Monitor Sysmon EID 13 for `TargetObject` containing `Microsoft\PowerShell\*\ExecutionPolicy` with `Details` values of "Bypass", "Unrestricted", or "RemoteSigned" originating from non-administrative processes or unexpected parent processes.

2. **PowerShell Cmdlet Monitoring**: Alert on PowerShell EID 4103 CommandInvocation events for `Set-ExecutionPolicy` cmdlet execution, particularly with `ExecutionPolicy` parameter values indicating policy relaxation and `Scope` parameters affecting system-wide settings.

3. **Command Line Analysis**: Detect Security EID 4688 process creation events with command lines containing `Set-ExecutionPolicy` combined with policy-weakening parameters, especially when executed by SYSTEM or from automated execution contexts.

4. **Process-Registry Correlation**: Correlate PowerShell process creation (Sysmon EID 1) with subsequent registry modifications to PowerShell execution policy keys within a short time window, indicating programmatic policy manipulation.

5. **Execution Policy Baseline Monitoring**: Establish baselines for legitimate execution policy changes and alert on deviations, particularly policy modifications occurring outside of approved maintenance windows or standard deployment processes.
