# T1040-4: Network Sniffing — Packet Capture Windows Command Prompt

## Technique Context

Network Sniffing (T1040) involves capturing network traffic to collect sensitive information in transit, including credentials, configuration data, or intelligence about network topology. Attackers commonly use this technique for credential harvesting and lateral movement planning. This specific test (T1040-4) demonstrates using Wireshark's tshark command-line tool through cmd.exe to capture network packets, representing a common approach where attackers leverage legitimate network analysis tools for malicious purposes.

The detection community focuses on monitoring for packet capture tool execution, especially when invoked programmatically, unusual command-line parameters indicating network interfaces or packet counts, and the presence of network sniffing tools in non-administrative contexts. The technique becomes particularly concerning when executed from memory, through remote shells, or with elevated privileges.

## What This Dataset Contains

This dataset captures a straightforward network sniffing attempt using tshark.exe. The key evidence appears in Security 4688 events showing the process execution chain: PowerShell spawning cmd.exe with the command `"cmd.exe" /c "c:\Program Files\Wireshark\tshark.exe" -i Ethernet -c 5`. The command specifies the Ethernet interface and limits capture to 5 packets.

Sysmon provides complementary telemetry with EID 1 ProcessCreate events for both whoami.exe (process ID 6844) and cmd.exe (process ID 4552). The cmd.exe creation event shows the full command line: `"cmd.exe" /c "c:\Program Files\Wireshark\tshark.exe" -i Ethernet -c 5`. Notably, the cmd.exe process exits with status 0x1 in Security 4689, suggesting the tshark execution failed.

Security 4703 shows PowerShell acquiring multiple high-level privileges including SeBackupPrivilege and SeSystemEnvironmentPrivilege, which could facilitate network capture operations. Sysmon EID 10 events capture PowerShell accessing both spawned processes with full access rights (0x1FFFFF).

The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) with no technique-specific script content.

## What This Dataset Does Not Contain

Most critically, this dataset lacks any Sysmon ProcessCreate event for tshark.exe itself, indicating the packet capture tool never actually executed successfully. The cmd.exe exit code 0x1 in Security 4689 confirms the command failed. This is likely because Wireshark/tshark was not installed on the test system, causing the command to fail with "file not found" or similar error.

The dataset also lacks network connection events (Sysmon EID 3) that would normally accompany successful packet capture operations, file creation events for captured packet files, and any DNS queries related to the sniffing activity. The sysmon-modular configuration's include-mode filtering would have captured tshark.exe execution if it had occurred, as network analysis tools typically match suspicious process patterns.

## Assessment

This dataset provides limited value for detection engineering focused on successful network sniffing, as the core technique execution failed. However, it offers valuable insight into the attempt pattern and command-line structure that detection engineers should monitor. The Security 4688 events with full command-line logging provide the primary detection opportunity, capturing the intent even when execution fails.

The telemetry quality is good for the events that occurred, with complete process chains, command lines, and privilege escalation context. For building robust detections of this technique, you would ideally want datasets showing successful tshark execution, packet file creation, and potentially network interface enumeration preceding the capture attempt.

## Detection Opportunities Present in This Data

1. **Command-line detection for tshark execution** - Security 4688 and Sysmon EID 1 events containing `tshark.exe` with network interface parameters (`-i`) and packet count limits (`-c`)

2. **Suspicious parent-child process relationships** - PowerShell spawning cmd.exe to execute packet capture tools, detectable through ParentImage fields in process creation events

3. **Network analysis tool enumeration** - Process creation events for common packet capture utilities (tshark, tcpdump, wireshark) especially when executed programmatically

4. **Privilege escalation preceding network operations** - Security 4703 events showing acquisition of backup and system privileges that could facilitate network sniffing

5. **Failed execution patterns** - Exit code analysis in Security 4689 events can identify failed attempts at running network capture tools, indicating reconnaissance or preparation phases
