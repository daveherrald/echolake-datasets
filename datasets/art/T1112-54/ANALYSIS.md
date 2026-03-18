# T1112-54: Modify Registry — Windows Auto Update Option to Notify before download

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers for defense evasion and persistence. The Windows Registry contains critical system configurations, security policies, and application settings that, when modified, can disable security features, establish persistence mechanisms, or alter system behavior to benefit an attacker. This specific test targets Windows Update policies, which attackers commonly manipulate to prevent security patches from being installed automatically, keeping systems vulnerable to known exploits. The detection community focuses on monitoring registry modifications to sensitive policy keys, particularly those affecting security controls like Windows Update, Windows Defender, UAC, and firewall settings.

## What This Dataset Contains

This dataset captures a successful registry modification executed through PowerShell spawning cmd.exe and reg.exe. The core attack sequence shows:

- **Security 4688**: PowerShell (PID 40164) spawning cmd.exe with command line `"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 2 /f"`
- **Security 4688**: cmd.exe spawning reg.exe with command line `reg  add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 2 /f`
- **Sysmon 1**: Process creation events for both cmd.exe and reg.exe, confirming the execution chain
- **Security 4689**: Process termination events showing successful completion (exit status 0x0)

The target registry modification sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions` to value 2, which configures Windows Update to "Notify before download" - effectively disabling automatic updates. The PowerShell logs contain only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content captured.

## What This Dataset Does Not Contain

This dataset lacks direct registry modification telemetry. While we see the reg.exe process creation and successful completion, there are no Sysmon Event ID 13 (Registry value set) events captured, likely because the sysmon-modular configuration doesn't monitor this particular registry path or the reg.exe tool bypassed the monitored registry access methods. We also don't see any Windows Security Event ID 4657 (Registry value modified) events, indicating the audit policy doesn't cover object access auditing for registry modifications. Additionally, there's no PowerShell script block logging of the actual registry modification command, suggesting it was executed through the cmd.exe spawn rather than native PowerShell registry cmdlets.

## Assessment

This dataset provides solid process execution telemetry for detecting registry modification attacks but lacks the registry-level telemetry that would provide definitive confirmation of the actual modification. The Security 4688 events with full command-line logging are excellent for detection, clearly showing the suspicious reg.exe command targeting Windows Update policies. The Sysmon process creation events add valuable context with process GUIDs, hashes, and parent-child relationships. However, the absence of registry modification events limits the dataset's utility for demonstrating complete attack chains and could lead to false negatives if attackers use alternative registry modification methods that don't spawn reg.exe.

## Detection Opportunities Present in This Data

1. **Command-line detection for reg.exe targeting Windows Update policies** - Security 4688 shows `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"` which is a high-fidelity indicator

2. **Process chain analysis for PowerShell spawning registry tools** - Sysmon 1 events show powershell.exe → cmd.exe → reg.exe execution chain, unusual for legitimate administration

3. **Registry tool execution from non-administrative contexts** - reg.exe execution for policy modification should trigger alerts when not from expected administrative tools

4. **Windows Update policy tampering via command line** - The specific AUOptions registry key modification can be detected through command-line pattern matching

5. **Suspicious privilege escalation context** - Security 4703 shows extensive privilege enabling for the PowerShell process, indicating potential administrative abuse
