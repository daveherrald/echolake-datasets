# T1003-2: OS Credential Dumping — Credential Dumping with NPPSpy

## Technique Context

T1003.002 focuses on credential dumping through OS credential stores, specifically targeting the Security Accounts Manager (SAM) and other credential repositories. NPPSpy is a classic persistence technique that installs a malicious Network Provider DLL to intercept credentials during Windows authentication flows. When users authenticate to network resources, the malicious provider captures plaintext credentials before they're processed by legitimate providers. This technique is particularly insidious because it operates at the system level and can capture credentials for any user authenticating on the compromised system. Detection engineers focus on monitoring registry modifications to NetworkProvider order, suspicious DLL installations in System32, and unusual Network Provider configurations.

## What This Dataset Contains

This dataset captures a successful NPPSpy installation executed via PowerShell. The Security channel shows the PowerShell process creation with the full command line in EID 4688: `"powershell.exe" & {Copy-Item "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll" -Destination "C:\Windows\System32\"...}` revealing the complete attack chain. Multiple PowerShell EID 4104 script block events capture the malicious PowerShell code, including `Copy-Item "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll" -Destination "C:\Windows\System32"` and the registry modifications.

Sysmon provides comprehensive coverage with EID 13 registry events showing the critical modifications: setting `HKLM\System\CurrentControlSet\Control\NetworkProvider\Order\PROVIDERORDER` to `RDPNP,P9NP,LanmanWorkstation,webclient,NPPSpy` (adding NPPSpy to the provider chain), and creating the NPPSpy service configuration at `HKLM\System\CurrentControlSet\Services\NPPSpy\NetworkProvider\` with Class=2, Name=NPPSpy, and ProviderPath pointing to the malicious DLL. The Sysmon EID 1 events show whoami.exe execution for discovery, and EID 10 process access events capture PowerShell accessing the whoami process.

## What This Dataset Does Not Contain

The dataset lacks the actual file copy operation of NPPSPY.dll to System32, suggesting either Defender blocked the file operation or the source file was missing. While the PowerShell script attempts the copy operation, no corresponding Sysmon EID 11 file creation event shows the malicious DLL being placed in System32. The dataset also doesn't contain any post-installation credential harvesting activity since NPPSpy requires a user logoff/logon cycle to become active. Network authentication events that would trigger the malicious provider aren't present. No file system events show the creation of C:\NPPSpy.txt where harvested credentials would be stored.

## Assessment

This dataset provides excellent telemetry for detecting NPPSpy installation attempts. The combination of PowerShell script block logging, Security process creation events with command lines, and Sysmon registry monitoring creates multiple high-fidelity detection opportunities. The registry modifications are particularly valuable as they represent the core persistence mechanism. The command line captured in Security EID 4688 provides the complete attack context in a single event. However, the absence of the actual DLL deployment limits the dataset's utility for detecting successful NPPSpy installations versus failed attempts. The telemetry strongly supports detection rule development for NPPSpy installation patterns.

## Detection Opportunities Present in This Data

1. Registry modification to NetworkProvider order adding suspicious provider names - Sysmon EID 13 modifying `HKLM\System\CurrentControlSet\Control\NetworkProvider\Order\PROVIDERORDER`

2. Creation of new NetworkProvider service registry keys - Sysmon EID 13 creating `HKLM\System\CurrentControlSet\Services\NPPSpy\NetworkProvider\*` entries

3. PowerShell script execution containing NPPSpy installation commands - PowerShell EID 4104 with "Copy-Item" and "ExternalPayloads\NPPSPY.dll"

4. Process creation with command lines containing NetworkProvider registry manipulation - Security EID 4688 with "Set-ItemProperty" and "NetworkProvider\Order"

5. PowerShell execution from SYSTEM context performing credential access preparation - Security EID 4688 showing NT AUTHORITY\SYSTEM executing PowerShell with suspicious parameters

6. Registry writes setting ProviderPath to System32 DLL locations - Sysmon EID 13 with TargetObject containing "ProviderPath" and Details containing "%SystemRoot%\System32\"
