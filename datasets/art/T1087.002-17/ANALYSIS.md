# T1087.002-17: Domain Account — Wevtutil - Discover NTLM Users Remote

## Technique Context

T1087.002 (Account Discovery: Domain Account) involves adversaries enumerating domain user accounts to understand the environment and identify targets for lateral movement or privilege escalation. This specific test simulates a technique where attackers use `wevtutil` to extract NTLM authentication events (Event ID 4776) from domain controllers, which can reveal domain user accounts that have recently authenticated.

The detection community focuses on unusual event log queries, especially those targeting authentication events, remote execution of event log utilities, and PowerShell scripts that perform DNS lookups against domain controllers. This technique is particularly concerning because it can be executed remotely and provides valuable reconnaissance data about active domain accounts.

## What This Dataset Contains

This dataset captures a PowerShell-based attack chain that attempts remote event log extraction via WMIC. The key events include:

**Process Creation Chain (Security 4688 events):**
- Initial PowerShell execution with command: `"powershell.exe" & {$target = $env:LOGONSERVER $target = $target.Trim("\\") $IpAddress = [System.Net.Dns]::GetHostAddresses($target) | select IPAddressToString -ExpandProperty IPAddressToString wmic.exe /node:$IpAddress process call create 'wevtutil epl Security C:\\ntlmusers.evtx /q:\"Event[System[(EventID=4776)]]\""'`
- WMIC execution attempting remote process creation: `"C:\Windows\System32\Wbem\WMIC.exe" "/node:fe80::fb37:8a73:8e4d:7614%8 192.168.4.12" process call create "wevtutil epl Security C:\\ntlmusers.evtx /q:\Event[System[(EventID=4776)]]""`

**PowerShell Script Block Logging (4104 events):** 
- PowerShell script that resolves `$env:LOGONSERVER` to IP addresses (IPv6 and IPv4: "fe80::fb37:8a73:8e4d:7614%8" and "192.168.4.12")
- DNS resolution via `[System.Net.Dns]::GetHostAddresses($target)`
- Command construction for remote wevtutil execution

**Sysmon Events:**
- Process creation for whoami.exe (EID 1) - likely reconnaissance
- Multiple PowerShell process creations (EID 1) showing the execution chain
- Process access events (EID 10) showing PowerShell accessing child processes
- Image load events (EID 7) for .NET components and security modules

**WMIC Exit Status:**
The Security event shows WMIC exiting with status `0xAC67`, indicating the remote execution attempt failed.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful remote execution or event log extraction. The WMIC process exits with an error code, suggesting the remote wevtutil command failed to execute on the target system. We don't see:

- Successful network connections to the domain controller
- Evidence of the target .evtx file being created locally
- Authentication events that would indicate successful remote access
- Any extracted NTLM authentication logs (Event ID 4776)

The sysmon-modular configuration filtered out the initial PowerShell process creation, though we can see the subsequent child processes. We also don't see network connection events (Sysmon EID 3) that would show the WMIC connection attempt details.

## Assessment

This dataset provides excellent telemetry for detecting the attempt phase of this technique. The combination of PowerShell script block logging, process creation events with full command lines, and Sysmon process monitoring creates multiple detection opportunities. The PowerShell DNS resolution activity, WMIC remote execution attempt, and the specific wevtutil command targeting Event ID 4776 are all highly indicative behaviors.

While the technique ultimately failed (as evidenced by the WMIC exit code), the detection value is high because the preparatory activities are well-captured. This represents a realistic scenario where defensive measures prevented successful execution but left clear evidence of the attempt.

## Detection Opportunities Present in This Data

1. **PowerShell DNS resolution of LOGONSERVER environment variable** - Script block contains `$env:LOGONSERVER` and `[System.Net.Dns]::GetHostAddresses($target)`

2. **WMIC remote process creation with event log utilities** - Command line contains `wmic.exe /node:` followed by `wevtutil epl Security`

3. **Wevtutil targeting NTLM authentication events** - Command specifically queries for `Event[System[(EventID=4776)]]`

4. **PowerShell script constructing remote event log extraction commands** - Script block shows dynamic construction of wevtutil commands with IP addresses

5. **Process chain from PowerShell to WMIC to attempted wevtutil** - Security 4688 events show parent-child relationship and command line progression

6. **Failed remote execution attempts** - WMIC exit code 0xAC67 indicates unsuccessful remote process creation

7. **PowerShell accessing spawned processes** - Sysmon EID 10 shows PowerShell with high-privilege access (0x1FFFFF) to child processes

8. **Domain controller reconnaissance via DNS lookups** - PowerShell performing DNS resolution against domain infrastructure
