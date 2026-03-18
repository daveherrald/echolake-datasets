# T1112-63: Modify Registry — Scarab Ransomware Defense Evasion Activities

## Technique Context

T1112 Modify Registry is a fundamental technique used by adversaries to alter Windows registry settings for persistence, defense evasion, and privilege escalation. Scarab ransomware specifically targets the CredSSP (Credential Security Support Provider) configuration to weaken authentication security controls. The technique modifies the `AllowEncryptionOracle` registry value to permit downgrade attacks against CredSSP, effectively allowing less secure authentication mechanisms that can be more easily exploited. Detection engineers focus on monitoring registry modifications to security-critical keys, particularly those involving authentication policies, UAC settings, and Windows Defender configurations. This specific variant is particularly concerning as it weakens network authentication security posture while appearing as legitimate administrative activity.

## What This Dataset Contains

This dataset captures a complete registry modification attack sequence targeting CredSSP security controls. The primary evidence is found in Sysmon EID 13 showing `reg.exe` (PID 13752) setting `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle` to `DWORD (0x00000002)`, which enables vulnerable encryption oracle remediation. The attack chain begins with PowerShell execution, followed by Security EID 4688 showing cmd.exe spawning with command line `"cmd.exe" /c reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2 /f`, and culminates with Security EID 4688 capturing the reg.exe process with the full registry modification command. Sysmon EID 1 events provide additional process creation context for both the command shell (ProcessGuid {9dc7570a-73b9-69b4-234e-000000001000}) and reg.exe (ProcessGuid {9dc7570a-73b9-69b4-254e-000000001000}) processes. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating the parent-child process relationships.

## What This Dataset Does Not Contain

The dataset lacks the initial PowerShell script content that orchestrated this attack, as the PowerShell channel only contains test framework boilerplate (Set-StrictMode and Set-ExecutionPolicy Bypass commands). No Sysmon ProcessCreate events exist for the parent PowerShell processes due to the sysmon-modular include-mode filtering that only captures processes matching known-suspicious patterns. The dataset doesn't show any Windows Defender blocking attempts or AMSI detection events, suggesting this technique executed without triggering real-time protection. Registry query events that might have preceded the modification are not captured, and there's no evidence of privilege escalation events that might have been required to modify HKLM registry keys. File system artifacts related to the attack script or any dropped payloads are not present in the telemetry.

## Assessment

This dataset provides excellent telemetry for detecting T1112 registry modification techniques, particularly those targeting authentication security controls. The combination of Security EID 4688 command-line logging and Sysmon EID 13 registry value monitoring creates a complete detection picture. The process lineage from PowerShell through cmd.exe to reg.exe is well-documented across both Security and Sysmon channels, enabling robust parent-child process correlation. The registry modification event includes the exact key path, value name, and data, providing high-fidelity indicators for detection rules. However, the absence of the triggering PowerShell script content limits understanding of the attack's initial vector and broader campaign context.

## Detection Opportunities Present in This Data

1. Monitor Sysmon EID 13 for modifications to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle` with value 2, which weakens authentication security
2. Detect Security EID 4688 process creation of reg.exe with command lines containing "AllowEncryptionOracle" and "/d 2" parameters
3. Create correlation rules linking PowerShell parent processes to cmd.exe children executing registry modification commands via process GUIDs
4. Alert on Sysmon EID 1 reg.exe process creation with command lines targeting CredSSP policy registry keys
5. Monitor for process access patterns (EID 10) where PowerShell accesses cmd.exe with full rights (0x1FFFFF) followed by registry tools
6. Detect Security EID 4688 cmd.exe processes with "/c reg add" command patterns targeting system policy registry locations
7. Build behavioral analytics detecting the specific process chain: powershell.exe → cmd.exe → reg.exe modifying authentication policies
8. Alert on registry modifications to security-critical paths performed by non-administrative tools or unexpected parent processes
