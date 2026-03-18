# T1112-33: Modify Registry — Windows Powershell Logging Disabled

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where attackers modify Windows registry keys to alter system behavior, disable security features, or establish persistence. This specific test focuses on disabling PowerShell logging capabilities by manipulating registry keys under `HKCU\Software\Policies\Microsoft\Windows\PowerShell\`. This is a critical anti-forensics technique because PowerShell logging provides extensive visibility into script execution, making it valuable for both legitimate administration and malicious activities. Attackers commonly target PowerShell logging settings to evade detection by security teams who rely on PowerShell event logs for threat hunting and incident response.

The detection community focuses heavily on monitoring registry modifications to security-relevant keys, particularly those affecting logging, Windows Defender, UAC, and other protective mechanisms. Registry modification events are considered high-fidelity indicators when targeting known defensive bypass locations.

## What This Dataset Contains

This dataset captures a PowerShell-executed registry modification attack that disables multiple PowerShell logging features. The attack chain begins with PowerShell process creation and proceeds through registry manipulation using the `reg.exe` utility.

The core malicious activity is visible in Security event 4688 showing cmd.exe execution with the comprehensive command line: `"cmd.exe" /c reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 0 /f & reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f & reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 0 /f & reg add HKCU\Software\Policies\Microsoft\Windows\PowerShell /v EnableScripts /t REG_DWORD /d 0 /f & reg delete HKCU\Software\Policies\Microsoft\Windows\PowerShell /v EnableScripts /f >nul 2>&1`

Sysmon captures the complete process execution chain with EID 1 events showing:
- PowerShell parent process (PID 43940)  
- cmd.exe child process (PID 7276) executing the batch command
- Five individual reg.exe processes modifying specific PowerShell logging keys:
  - ModuleLogging/EnableModuleLogging → 0
  - ScriptBlockLogging/EnableScriptBlockLogging → 0  
  - Transcription/EnableTranscripting → 0
  - PowerShell/EnableScripts → 0 (then deleted)

Security events 4688/4689 provide comprehensive process creation/termination coverage with full command lines for all processes in the chain.

## What This Dataset Does Not Contain

This dataset lacks the actual registry modification events (Sysmon EID 13) that would show the specific registry value changes being made. This gap exists because the sysmon-modular configuration may not be capturing all registry modifications, or the events were filtered out during collection.

The PowerShell channel contains only test framework boilerplate with Set-StrictMode and Set-ExecutionPolicy activities rather than the actual malicious PowerShell script that initiated the registry changes. This suggests the attack was executed through a minimal PowerShell wrapper rather than a comprehensive script.

The dataset also doesn't contain any Windows Defender detection events, indicating this registry modification technique executed successfully without triggering real-time protection alerts.

## Assessment

This dataset provides excellent process-level telemetry for detecting PowerShell logging bypass attempts through registry modification. The Security channel's complete process lineage with command-line logging offers the primary detection value, clearly showing the suspicious registry operations targeting PowerShell security features.

While the absence of direct registry modification events (Sysmon EID 13) limits visibility into the actual values being changed, the process execution telemetry is sufficient for high-confidence detection. The attack pattern of multiple sequential reg.exe processes targeting PowerShell policy keys is highly distinctive and rarely seen in legitimate administration.

The dataset would be stronger with registry modification events and the actual PowerShell commands that triggered the attack, but the existing telemetry provides robust detection opportunities for this evasion technique.

## Detection Opportunities Present in This Data

1. **PowerShell Logging Bypass Command Pattern** - Alert on cmd.exe or reg.exe command lines containing multiple PowerShell policy registry paths (ModuleLogging, ScriptBlockLogging, Transcription) with disable values

2. **Sequential Registry Tool Execution** - Detect multiple reg.exe processes spawned in rapid succession from the same parent, especially targeting HKCU\Software\Policies\Microsoft\Windows\PowerShell

3. **PowerShell Security Policy Tampering** - Monitor process creation events where reg.exe targets any PowerShell logging-related registry keys with /d 0 (disable) parameters

4. **Batch Registry Modification Pattern** - Flag cmd.exe execution containing chained registry commands (&& or & operators) that disable multiple security logging features

5. **PowerShell Spawning Registry Tools** - Alert when PowerShell processes spawn cmd.exe or reg.exe with arguments targeting Windows security policy registry locations

6. **Security Logging Bypass Sequence** - Correlate rapid sequential process creation of registry tools targeting EnableModuleLogging, EnableScriptBlockLogging, and EnableTranscripting within a short time window
