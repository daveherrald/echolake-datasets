# T1112-4: Modify Registry — Use Powershell to Modify registry to store logon credentials

## Technique Context

T1112 (Modify Registry) is a fundamental persistence and defense evasion technique where attackers modify Windows registry keys to maintain access or alter system behavior. This specific test (T1112-4) targets the WDigest authentication provider by setting the `UseLogonCredential` registry value to 1 under `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. This configuration forces Windows to store plaintext credentials in LSASS memory, enabling subsequent credential harvesting attacks like T1003. Detection engineers focus on monitoring registry modifications to security-sensitive keys, PowerShell execution patterns, and privilege escalation activities that facilitate credential access.

## What This Dataset Contains

The core technique evidence is captured in Sysmon EID 13, showing the registry modification: `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` set to `DWORD (0x00000001)` by PowerShell process 43288. Security EID 4688 captures the PowerShell process creation with the full command line: `"powershell.exe" & {Set-ItemProperty -Force -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value '1' -ErrorAction Ignore}`. PowerShell EID 4103 logs the `Set-ItemProperty` cmdlet execution with all parameters, while EID 4104 captures the script blocks containing the registry modification commands. Multiple Sysmon EID 1 events show PowerShell process creations, including the technique execution process (43288) spawned from another PowerShell process (43660). Process access events (EID 10) capture PowerShell accessing other processes with high privileges (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks any evidence of Windows Defender blocking the technique, as all processes exit successfully (exit status 0x0 in Security EID 4689). There are no registry access denial events or ERROR status codes that would indicate endpoint protection interference. The sysmon-modular configuration's include-mode filtering means many benign processes aren't captured in Sysmon EID 1, but PowerShell is included due to its T1059.001 rule coverage. No network connections or file system artifacts beyond PowerShell startup profiles are present. The dataset doesn't show the follow-on credential harvesting that this registry modification enables.

## Assessment

This dataset provides excellent telemetry for detecting WDigest credential storage enablement. The combination of Sysmon registry monitoring (EID 13), Security process auditing (EID 4688), and PowerShell logging (EIDs 4103/4104) creates multiple detection layers with high fidelity. The complete command-line capture in Security events and detailed PowerShell parameter binding in EID 4103 offer precise indicators. Registry value monitoring provides the most direct evidence of the technique's success. The data quality is strong for building behavioral detections around PowerShell-based registry modifications to authentication providers.

## Detection Opportunities Present in This Data

1. Registry value set events (Sysmon EID 13) targeting `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` with value 1
2. PowerShell process creation (Security EID 4688) with command lines containing "WDigest" and "UseLogonCredential" registry paths
3. PowerShell cmdlet execution (EID 4103) of `Set-ItemProperty` targeting WDigest registry key with credential-related parameters
4. PowerShell script block logging (EID 4104) containing WDigest registry modification commands
5. Process access events (Sysmon EID 10) showing PowerShell with high privileges (0x1FFFFF) accessing other processes
6. Correlation of PowerShell execution with immediate registry modifications to authentication provider settings
7. Behavioral pattern of registry force-setting (`-Force` parameter) authentication provider configurations via PowerShell
