# T1095-2: Non-Application Layer Protocol — Netcat C2

## Technique Context

T1095 (Non-Application Layer Protocol) involves adversaries using protocols other than HTTP/HTTPS for command and control communications. This technique is attractive to attackers because it can bypass network security controls that focus on web traffic inspection, and it's often harder to detect since the traffic may blend with legitimate network protocols like DNS, ICMP, or raw TCP/UDP. The most common implementation involves tools like netcat, which can establish direct TCP/UDP connections for C2 purposes. Detection engineering typically focuses on unusual network connections, non-standard ports for services, process execution patterns involving network tools, and behavioral analytics around command execution and data exfiltration patterns.

## What This Dataset Contains

This dataset captures the execution of netcat from the Nmap package for a basic TCP connection test. The key telemetry shows:

**Process execution chain:** PowerShell spawns another PowerShell instance with command line `"powershell.exe" & {cmd /c \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe\" 127.0.0.1 80}`, which then spawns cmd.exe with command line `"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe 127.0.0.1 80`.

**PowerShell script blocks:** The PowerShell logs show script block creation for `& {cmd /c \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1095\nmap-7.80\ncat.exe\" 127.0.0.1 80}`, clearly revealing the netcat execution attempt.

**Process access events:** Sysmon EID 10 shows PowerShell processes accessing other processes with PROCESS_ALL_ACCESS (0x1FFFFF), indicating process injection detection capabilities.

**File operations:** Both PowerShell instances create PowerShell profile data files, showing normal PowerShell initialization behavior.

**Exit codes:** The cmd.exe process exits with status 0x1, suggesting the netcat connection failed (likely because no service was listening on localhost:80).

## What This Dataset Does Not Contain

Critically missing from this dataset are **network connection events**. There are no Sysmon EID 3 (Network Connection) events, which would normally capture the actual TCP connection attempt to 127.0.0.1:80. This absence indicates either:
1. The netcat process failed to start or crashed immediately
2. Windows Defender may have blocked the execution
3. The target service wasn't available and the connection failed before establishing

The dataset also lacks **DNS query events** (Sysmon EID 22) and shows no **ProcessCreate events for ncat.exe itself**. The sysmon-modular config's include-mode filtering for ProcessCreate events means ncat.exe wasn't considered a suspicious binary worth capturing, which is a significant gap for this technique.

## Assessment

This dataset provides limited detection value for T1095 because it captures the attempt rather than the actual technique execution. The PowerShell telemetry is excellent for detecting the command execution and tool invocation, but the absence of network telemetry severely limits its utility for understanding the network-based aspects of this technique. The process chain and command-line evidence are valuable for detection, but defenders need network connection logs to fully analyze non-application layer protocol communications. This dataset would be significantly stronger with successful netcat execution and resulting network telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell script block analysis** - Monitor EID 4104 for script blocks containing network tool invocations like "ncat.exe", "nc.exe", or similar utilities with IP addresses and ports

2. **Suspicious command line patterns** - Alert on Security EID 4688 command lines containing network utilities executed via cmd.exe with IP addresses and port numbers (e.g., `cmd.exe /c *.exe 127.0.0.1 80`)

3. **PowerShell process spawning cmd.exe** - Detect when PowerShell creates cmd.exe processes, especially with command lines containing external executables and network parameters

4. **External tool execution paths** - Monitor for process execution from non-standard directories like `\AtomicRedTeam\atomics\..\ExternalPayloads\` or other staging locations

5. **Failed network tool execution** - Correlate cmd.exe processes with exit code 0x1 when command lines contain network utility patterns, indicating potential blocked or failed C2 attempts

6. **PowerShell process access patterns** - Analyze Sysmon EID 10 events where PowerShell processes access other processes with full access rights, which may indicate process injection or advanced PowerShell-based attacks
