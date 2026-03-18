# T1112-5: Modify Registry — Add domain to Trusted sites Zone

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries alter Windows registry keys to undermine security controls, establish persistence, or modify system behavior. The specific variant tested here involves manipulating Internet Explorer's Zone Map settings to add domains to the Trusted Sites zone. This technique is commonly used by malware to bypass browser security restrictions and enable the execution of active content from attacker-controlled domains. The Trusted Sites zone (Zone 2) has relaxed security settings that allow scripts, ActiveX controls, and other potentially dangerous content to execute without user prompts.

Detection engineers typically focus on monitoring registry modifications to security-relevant keys, particularly those related to browser security zones, Windows Defender exclusions, startup locations, and service configurations. The Internet Settings ZoneMap registry path is a high-fidelity indicator when modified programmatically.

## What This Dataset Contains

This dataset captures a PowerShell-based registry modification that adds a malicious domain to the Internet Explorer Trusted Sites zone. The core malicious activity appears in Security event 4688, which shows the PowerShell process creation with the full command line: `"powershell.exe" & {$key= "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\bad-domain.com\" $name ="bad-subdomain" new-item $key -Name $name -Force new-itemproperty $key$name -Name https -Value 2 -Type DWORD; new-itemproperty $key$name -Name http -Value 2 -Type DWORD; new-itemproperty $key$name -Name * -Value 2 -Type DWORD;}`.

PowerShell module logging (events 4103) captures the individual cmdlet invocations:
- `New-Item` creating the registry key path for "bad-domain.com\bad-subdomain"
- Three `New-ItemProperty` calls setting DWORD values of 2 for https, http, and wildcard protocols

PowerShell script block logging (event 4104) records the script content, confirming the registry modification operations. Sysmon captures process creation events (EID 1) for both the parent and child PowerShell processes, along with extensive DLL loading events (EID 7) as PowerShell initializes the .NET runtime.

## What This Dataset Does Not Contain

Notably absent are Sysmon registry modification events (EID 13), which should have captured the actual registry writes. This gap suggests either the sysmon-modular configuration filters out HKCU registry modifications, or these events were not generated for another reason. Without EID 13 events, we cannot confirm the registry changes were successfully written to disk.

The dataset also lacks any Windows Defender alerts or blocks, indicating this technique executed without triggering real-time protection. No file system activity beyond PowerShell profile creation is captured, and there are no network connections that might indicate the malicious domain was actually accessed.

## Assessment

This dataset provides good coverage for detecting PowerShell-based registry modifications through process creation and PowerShell logging channels. The Security channel's command-line logging and PowerShell's module/script block logging offer multiple detection vectors. However, the absence of Sysmon registry events (EID 13) is a significant limitation for confirming the actual registry modifications occurred. For comprehensive T1112 detection, organizations need both process-level indicators (captured here) and registry-level telemetry (missing here).

The data quality is high for building detections around suspicious PowerShell usage and specific cmdlet patterns, but would be stronger with actual registry modification evidence.

## Detection Opportunities Present in This Data

1. **PowerShell command line containing Internet Settings ZoneMap paths** - Security 4688 events with command lines referencing `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains`

2. **New-ItemProperty cmdlet usage for browser security zones** - PowerShell 4103 events showing `New-ItemProperty` with registry paths containing "ZoneMap\Domains" and value 2 (Trusted Sites zone)

3. **PowerShell script blocks modifying browser security settings** - PowerShell 4104 events containing registry modification operations targeting Internet zone configuration

4. **Suspicious domain names in ZoneMap operations** - Command lines or script blocks containing obviously malicious domains like "bad-domain.com" in registry paths

5. **Bulk registry property creation for multiple protocols** - Rapid succession of New-ItemProperty operations creating https, http, and wildcard entries for the same domain path

6. **PowerShell process chains with registry modification intent** - Sysmon 1 events showing PowerShell spawning from PowerShell with command lines containing registry cmdlets and security zone paths
