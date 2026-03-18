# T1112-6: Modify Registry — Javascript in registry

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by attackers to maintain persistence, escalate privileges, and evade detection by modifying Windows registry keys and values. The detection community focuses heavily on monitoring registry modifications to security-relevant keys, particularly those used for persistence mechanisms, security controls, and execution paths. This specific test variant involves placing JavaScript code (`<script>`) into a registry value, which can be leveraged for various malicious purposes including web browser exploitation, persistence through browser extensions, or bypassing security controls that parse registry-stored web content.

Registry modifications are a cornerstone of Windows attack techniques, with defenders typically monitoring for changes to Run keys, COM object registrations, service configurations, and security policy settings. The placement of script tags in registry values represents a more subtle form of registry abuse that may not trigger traditional persistence-focused detection rules.

## What This Dataset Contains

This dataset captures a PowerShell-based registry modification that writes JavaScript content to the Windows registry. The core technique execution is visible in Security event 4688: `"powershell.exe" & {New-ItemProperty \"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name T1112 -Value \"<script>\"}`. 

The PowerShell activity is well-documented across multiple log sources:
- PowerShell script block logging (EID 4104) captures the actual command: `New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name T1112 -Value "<script>"`
- PowerShell command invocation logging (EID 4103) shows the cmdlet execution with parameters
- Sysmon captures multiple process creation events for PowerShell instances (EIDs 1, 7, 10, 11, 17)
- Security logs show process creation (EID 4688) and termination (EID 4689) events with full command lines

The registry target is `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, a location that controls Internet Explorer and web browser security settings. The test creates a new registry property named "T1112" with the value `<script>`, demonstrating how malicious JavaScript could be embedded in registry locations that browsers or web-enabled applications might parse.

## What This Dataset Does Not Contain

This dataset lacks the actual registry modification telemetry itself. Neither Sysmon registry events (EIDs 12, 13, 14) nor Windows Security registry auditing events are present in the collected logs. This is likely due to the Sysmon configuration using selective filtering that doesn't capture registry operations, and Windows audit policy not being configured for object access auditing.

The dataset also doesn't contain any evidence of the registry value being subsequently accessed, parsed, or executed by browsers or other applications. The test focuses purely on the initial placement of the malicious content rather than its activation or exploitation.

Process telemetry is incomplete due to sysmon-modular's include-mode filtering for ProcessCreate events — only processes matching suspicious patterns (like PowerShell) are captured, while standard system processes involved in the registry operation are filtered out.

## Assessment

The dataset provides excellent coverage for detecting PowerShell-based registry manipulation attempts. The combination of Security 4688 events with command-line logging and PowerShell script block/module logging creates multiple detection opportunities for this type of registry abuse. However, the absence of actual registry modification telemetry significantly limits the dataset's utility for building comprehensive registry-focused detections.

For building robust T1112 detections, this dataset is most valuable for identifying the delivery mechanism (PowerShell commands targeting registry APIs) rather than the registry changes themselves. Detection engineers would need additional data sources with proper registry auditing enabled to create complete coverage of registry modification techniques.

## Detection Opportunities Present in This Data

1. PowerShell execution with registry manipulation cmdlets (New-ItemProperty, Set-ItemProperty) targeting security-relevant registry paths
2. Script block content containing registry modification commands with suspicious values (script tags, encoded content, etc.)
3. Process command lines containing registry paths commonly abused for persistence or security bypass
4. PowerShell module loading patterns associated with registry manipulation activities
5. Execution of PowerShell with arguments containing both registry paths and script/code content in the same command
6. Multiple PowerShell process spawning patterns that may indicate automated registry modification campaigns
7. PowerShell accessing child processes (whoami.exe) during registry operations, suggesting enumeration activities
