# T1018-8: Remote System Discovery — Remote System Discovery - nslookup

## Technique Context

T1018 (Remote System Discovery) involves adversaries attempting to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for lateral movement. This technique is fundamental to network reconnaissance and is commonly observed in the early stages of post-exploitation activities. Attackers use various tools and methods to discover remote systems, including network scanning utilities, ARP tables, DNS lookups, and built-in Windows commands.

The nslookup utility is particularly interesting because it's a legitimate administrative tool that can be abused for reconnaissance without requiring additional tools. By systematically querying IP addresses, attackers can identify active hosts and potentially gather hostname information. This specific test demonstrates a common pattern where attackers use PowerShell to orchestrate systematic network scanning using native Windows utilities, making detection more challenging as it blends with legitimate administrative activity.

## What This Dataset Contains

This dataset captures a PowerShell-driven network reconnaissance attack that systematically scans the local subnet using nslookup. The attack chain begins with Security EID 4688 events showing the creation of a PowerShell process with the command line `"powershell.exe" & {$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1] $pieces = $localip.split(".") $firstOctet = $pieces[0] $secondOctet = $pieces[1] $thirdOctet = $pieces[2] foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}}`.

The execution generates a clear process chain visible in both Security and Sysmon logs. Security EID 4688 events show the systematic creation of cmd.exe processes with commands like `"C:\Windows\system32\cmd.exe" /c nslookup 192.168.4.1` through `"C:\Windows\system32\cmd.exe" /c nslookup 192.168.4.32` (where the scan was apparently interrupted). Each cmd.exe process spawns an nslookup.exe process with corresponding command lines like `nslookup 192.168.4.1`.

Sysmon provides complementary telemetry through EID 1 (Process Create) events that capture the same process creation activity with additional context including process GUIDs, parent-child relationships, and hash information. The PowerShell script block logging in EID 4104 events captures the actual script content: `& {$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1] $pieces = $localip.split(".") $firstOctet = $pieces[0] $secondOctet = $pieces[1] $thirdOctet = $pieces[2] foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}}`.

The dataset also contains Sysmon EID 10 (Process Access) events showing the PowerShell process accessing each cmd.exe and nslookup.exe process with `GrantedAccess: 0x1FFFFF`, indicating the parent process monitoring its children.

## What This Dataset Does Not Contain

The dataset does not contain the actual DNS query results or network traffic that would show whether the nslookup commands successfully resolved hostnames or received responses. Sysmon network connection events (EID 3) are not present, which means we cannot observe the actual DNS queries being transmitted. The scan appears to have been interrupted or limited, as it only covers IP addresses 192.168.4.1 through approximately 192.168.4.32, rather than the full /24 subnet scan (1-255) intended by the script.

DNS query logging from the Windows DNS Client or network-level DNS transaction logs are not available, which would provide the clearest evidence of the reconnaissance activity's success. The dataset also lacks any process tree visualization that would clearly show the fan-out pattern of the parent PowerShell process spawning multiple cmd.exe children in rapid succession.

File system events showing the initial PowerShell script creation or execution are not present, and there are no Windows Event Log entries from the DNS Client service that might indicate the volume of DNS queries being generated.

## Assessment

This dataset provides excellent coverage of the process-level telemetry for detecting PowerShell-orchestrated network reconnaissance using native Windows utilities. The combination of Security audit logs with command line logging and Sysmon process creation events creates a comprehensive view of the attack pattern. The PowerShell script block logging is particularly valuable as it captures the exact reconnaissance logic, including the systematic IP address generation.

The process creation telemetry clearly shows the abnormal pattern of a single PowerShell process rapidly spawning numerous cmd.exe processes with nslookup commands targeting sequential IP addresses. This behavioral signature is highly detectable and would be difficult for an attacker to obfuscate without changing their fundamental approach.

However, the dataset's detection value is somewhat limited by the absence of network-level telemetry and DNS query logging, which would provide confirmation that the reconnaissance was actually successful rather than just attempted. The early termination of the scan also means we don't see the full volume pattern that would be generated by a complete /24 subnet scan.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Pattern Detection** - Monitor EID 4104 events for PowerShell scripts containing network reconnaissance patterns like `ipconfig | findstr`, IP address parsing logic, and loops executing network utilities like nslookup or ping.

2. **Rapid Sequential Process Creation** - Detect a single parent process (PowerShell) spawning multiple cmd.exe processes in rapid succession (within seconds) with similar command line patterns.

3. **Sequential IP Address Scanning Pattern** - Monitor for cmd.exe processes with nslookup command lines targeting sequential IP addresses within the same subnet (e.g., 192.168.4.1, 192.168.4.2, 192.168.4.3).

4. **Volume-Based nslookup Anomaly Detection** - Establish baseline usage of nslookup.exe and alert when usage exceeds normal thresholds, particularly when executed programmatically rather than interactively.

5. **PowerShell Network Reconnaissance Command Patterns** - Create signatures for PowerShell scripts that combine ipconfig output parsing with loops that execute network discovery utilities.

6. **Process Tree Fan-Out Detection** - Monitor for process trees where a single process creates an unusually high number of child processes executing the same utility with systematically varied arguments.

7. **Cross-Process Access Pattern** - Use Sysmon EID 10 events to detect when a PowerShell process is accessing multiple cmd.exe and nslookup.exe processes, indicating programmatic control rather than interactive usage.
