# T1012-2: Query Registry — Query Registry with Powershell cmdlets

## Technique Context

T1012 Query Registry is a fundamental Discovery technique where adversaries enumerate Windows registry keys and values to gather system configuration information, installed software, user data, and persistence mechanisms. The Windows registry serves as a central database containing critical system and application configuration data, making it a prime target for reconnaissance activities.

Attackers commonly query registry locations like Run keys for persistence mechanisms, software installation paths, system version information, and user-specific configurations. PowerShell's registry cmdlets (Get-Item, Get-ChildItem, Get-ItemProperty) provide native, living-off-the-land capabilities for registry enumeration without requiring additional tools. The detection community focuses on monitoring for systematic registry queries targeting known high-value locations, especially when performed in rapid succession or targeting multiple persistence-related keys.

## What This Dataset Contains

This dataset captures a comprehensive PowerShell-based registry enumeration script executed via Atomic Red Team. The activity is clearly visible across multiple data sources:

**Security Event 4688** shows the PowerShell process creation with the full command line revealing extensive registry queries: `"powershell.exe" & {Get-Item -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"...` targeting 23 different registry paths including Run keys, Winlogon settings, services, and startup locations.

**PowerShell EID 4103/4104** events provide granular visibility into each registry cmdlet execution. Key events include:
- `Get-Item -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"`
- `Get-ChildItem -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\" | findstr Windows`
- Multiple queries to persistence locations like `HKLM:Software\Microsoft\Windows\CurrentVersion\Run`
- Service enumeration via `Get-ChildItem -Path "HKLM:system\currentcontrolset\services"`
- `NonTerminatingError` events for non-existent keys like RunServicesOnce, Winlogon\Notify

**Sysmon EID 1** events capture both the initial PowerShell process (PID 6176) with the full registry enumeration script and the child findstr.exe process (PID 3692) used for filtering registry output.

The PowerShell channel also shows error handling patterns where the script attempts to access registry keys that don't exist on modern Windows systems, generating `NonTerminatingError` entries.

## What This Dataset Does Not Contain

This dataset lacks actual registry content or values - only the query attempts are logged. Registry access auditing (Security event 4656/4663) is not enabled, so there's no granular tracking of which specific registry values were read successfully versus failed attempts.

Process creation events for some expected child processes may be missing due to the sysmon-modular configuration's include-mode filtering for ProcessCreate events. The dataset shows successful creation events for whoami.exe and findstr.exe but may not capture all process spawning.

Windows Defender is active but doesn't block this technique since it represents legitimate PowerShell cmdlet usage against standard registry locations without malicious payloads.

## Assessment

This dataset provides excellent telemetry for detecting T1012 registry enumeration via PowerShell. The combination of command-line logging in Security events and detailed PowerShell execution logging creates comprehensive visibility into both the high-level attack pattern and individual registry queries.

The PowerShell channel data is particularly valuable, showing not just successful queries but also failed attempts against non-existent keys, which can be indicative of reconnaissance scripts designed for multiple Windows versions. The systematic nature of querying persistence-related registry locations creates clear behavioral indicators.

The data quality is very high for building detections around bulk registry enumeration, PowerShell-based discovery activities, and persistence location reconnaissance.

## Detection Opportunities Present in This Data

1. **Bulk Registry Enumeration Detection** - Multiple rapid-fire PowerShell registry queries (4103 events) within a short timeframe targeting diverse registry locations

2. **Persistence Location Reconnaissance** - Sequential queries to known persistence registry keys: Run, RunOnce, Winlogon, Services, Active Setup components

3. **PowerShell Registry Discovery Pattern** - Command line analysis for PowerShell processes executing Get-Item/Get-ChildItem against HKLM registry paths

4. **Registry Query Error Patterns** - Multiple NonTerminatingError events for non-existent registry keys indicating automated reconnaissance scripts

5. **Process Tree Analysis** - PowerShell spawning findstr.exe for registry output filtering, indicating systematic enumeration rather than targeted queries

6. **PowerShell Script Block Analysis** - EID 4104 events showing registry-focused PowerShell code execution patterns

7. **High-Value Registry Path Targeting** - Focus detection on queries to SOFTWARE\Microsoft\Windows\CurrentVersion\Run*, Winlogon, and Services registry locations
