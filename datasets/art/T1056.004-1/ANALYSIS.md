# T1056.004-1: Credential API Hooking — Hook PowerShell TLS Encrypt/Decrypt Messages

## Technique Context

T1056.004 (Credential API Hooking) involves adversaries intercepting function calls within libraries or processes to capture credentials or other sensitive information. This technique targets API functions responsible for authentication, encryption, or credential handling. In the context of TLS communications, attackers hook into encryption/decryption functions to capture plaintext data before encryption or after decryption, potentially exposing credentials, session tokens, or other sensitive information transmitted over supposedly secure channels.

The detection community focuses on several key indicators for this technique: DLL injection into processes (particularly those handling sensitive data), API hooking indicators like CreateRemoteThread events, unexpected DLL loads in target processes, and behavioral anomalies in network communication patterns. PowerShell is a particularly attractive target for credential API hooking because it frequently handles authentication tokens, makes web requests, and interacts with various Windows APIs that process credentials.

## What This Dataset Contains

This dataset captures a successful credential API hooking attack against PowerShell using mavinject.exe for DLL injection. The attack flow is clearly visible across multiple event sources:

The PowerShell script block logging (EID 4104) captures the attack payload: `mavinject $pid /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1056.004\bin\T1056.004x64.dll"` followed by `Invoke-WebRequest https://www.example.com -UseBasicParsing`.

Security event 4688 shows the process creation chain: initial PowerShell (PID 43364) spawns another PowerShell process (PID 43968) with the attack command line, which then launches mavinject.exe (PID 43440) with arguments `"C:\Windows\system32\mavinject.exe" 43968 /INJECTRUNNING C:\AtomicRedTeam\atomics\T1056.004\bin\T1056.004x64.dll`.

Sysmon provides detailed injection telemetry through multiple event types:
- EID 1 process creation events for all components (whoami.exe, PowerShell child process, mavinject.exe)
- EID 8 CreateRemoteThread showing mavinject.exe injecting into the PowerShell process with StartFunction `LoadLibraryW`
- EID 10 process access events showing cross-process access with GrantedAccess `0x1FFFFF`
- EID 7 image load events tracking DLL loads in the target PowerShell process

Network activity is captured via Sysmon EID 22 DNS query for `www.example.com` and EID 3 network connection, confirming the web request executed after DLL injection.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide deeper insight into the hooking mechanism itself. Most notably, there are no Sysmon EID 7 events showing the actual malicious DLL (`T1056.004x64.dll`) being loaded into the target PowerShell process, which would be expected if the injection succeeded. This suggests either the DLL injection failed, the DLL wasn't properly instrumented for monitoring, or the sysmon-modular configuration filtered out this particular image load event.

The dataset also doesn't contain any evidence of the actual API hooking behavior - no registry modifications, file writes that would indicate captured credentials, or additional network connections that might result from exfiltrating hooked data. There are no Windows Defender quarantine events despite the clear presence of malicious activity, and no process hollowing or other advanced injection techniques are evident beyond the basic DLL injection via mavinject.

The PowerShell operational logs contain mostly test framework boilerplate rather than detailed script execution logs that might reveal the hooking implementation details.

## Assessment

This dataset provides excellent coverage of the initial injection phase of credential API hooking attacks. The combination of Security event process creation logging, Sysmon process injection events (EID 8, 10), and PowerShell script block logging creates a comprehensive view of how attackers use legitimate Windows tools like mavinject.exe to inject malicious DLLs into target processes.

The data quality is particularly strong for detection engineering focused on the injection vectors rather than the post-injection hooking behavior. The clear process lineage, detailed command lines, and precise timing make this dataset valuable for building detections around mavinject abuse, PowerShell-based injection commands, and cross-process access patterns.

However, the dataset's utility is limited for understanding the full lifecycle of credential API hooking attacks, as it lacks evidence of successful hooking implementation or credential capture. This makes it more suitable for detecting the attack setup phase rather than the data exfiltration phase.

## Detection Opportunities Present in This Data

1. **Mavinject Process Creation with DLL Path Arguments** - Security EID 4688 and Sysmon EID 1 showing mavinject.exe launched with `/INJECTRUNNING` parameter and external DLL path from non-system locations

2. **PowerShell Script Block with Mavinject Commands** - PowerShell EID 4104 containing `mavinject $pid /INJECTRUNNING` patterns combined with suspicious DLL paths

3. **CreateRemoteThread from Mavinject to PowerShell** - Sysmon EID 8 showing mavinject.exe creating remote threads in PowerShell processes with StartFunction `LoadLibraryW`

4. **High-Privilege Process Access for Injection** - Sysmon EID 10 events showing GrantedAccess `0x1FFFFF` (PROCESS_ALL_ACCESS) from mavinject to PowerShell processes

5. **Process Chain Anomaly Detection** - PowerShell spawning mavinject.exe as captured in Security EID 4688 ParentProcessName relationships

6. **Suspicious DLL Path References** - Command line arguments containing paths to non-standard directories (`C:\AtomicRedTeam\atomics\`) in both Security and Sysmon process creation events

7. **Combined Injection and Network Activity** - Correlation of DLL injection events (EID 8) with immediate DNS queries (EID 22) and network connections (EID 3) to external domains

8. **PowerShell Child Process with Injection Commands** - Detection of PowerShell processes created with command lines containing both injection utilities and network communication cmdlets
