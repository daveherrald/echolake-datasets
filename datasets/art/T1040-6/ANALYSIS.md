# T1040-6: Network Sniffing — Windows Internal pktmon capture

## Technique Context

T1040 Network Sniffing involves adversaries intercepting network traffic to capture data transmitted across networks. This technique is commonly used for credential harvesting, reconnaissance, and data exfiltration. Attackers may use various tools ranging from simple packet capture utilities to sophisticated network monitoring software.

The Windows Packet Monitor (pktmon.exe) utility, introduced in Windows 10 version 1809 and Windows Server 2019, provides legitimate network troubleshooting capabilities but can be abused by attackers for network sniffing. Unlike external tools like Wireshark or tcpdump, pktmon is a signed Windows binary that may evade detection in environments where unsigned tools are blocked. The detection community focuses on monitoring pktmon execution patterns, particularly when combined with ETW (Event Tracing for Windows) logging and file output to temporary locations.

## What This Dataset Contains

This dataset captures a complete pktmon network sniffing sequence executed through PowerShell. The key evidence includes:

**Process execution chain:** PowerShell → cmd.exe → pktmon.exe with the command `"cmd.exe" /c pktmon.exe start --etw  -f %TEMP%\t1040.etl & TIMEOUT /T 5 >nul 2>&1 & pktmon.exe stop`. Security event 4688 shows two separate pktmon.exe executions: first with `pktmon.exe  start --etw  -f C:\Windows\TEMP\t1040.etl` and second with `pktmon.exe  stop`.

**Sysmon process creation events:** EID 1 captures both pktmon processes with the tagged rule `technique_id=T1040,technique_name=Network Sniffing`, confirming the technique identification. The processes run with SYSTEM privileges and show the full command lines including the ETL output file path.

**File system artifacts:** Sysmon EID 11 events document the creation of `C:\Windows\Temp\t1040.etl` and `C:\Windows\Temp\t1040.etl.tmp` files, providing evidence of the packet capture output. These files are tagged with `technique_id=T1574.010,technique_name=Services File Permissions Weakness`.

**Timing evidence:** The dataset shows a 5-second capture window between pktmon start (13:57:30.007) and stop (13:57:30.271), with the timeout.exe process running concurrently as specified in the batch command.

## What This Dataset Does Not Contain

The dataset lacks several elements that would strengthen detection coverage:

**Network-level telemetry:** There are no Sysmon EID 3 (Network Connection) events showing actual network traffic being captured, which would help correlate the sniffing activity with specific network flows.

**ETL file analysis:** The dataset doesn't include analysis of the actual packet capture content within the generated ETL file, which could reveal the scope and sensitivity of captured data.

**Driver-level events:** The dataset shows a Security EID 4703 event for SeLoadDriverPrivilege being enabled, but lacks detailed driver load events that pktmon may trigger at the kernel level for packet interception.

**PowerShell script content:** The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the actual test script commands, limiting visibility into the attack simulation logic.

## Assessment

This dataset provides excellent coverage for detecting pktmon-based network sniffing techniques. The combination of Security 4688 command-line logging and Sysmon process creation events captures the complete execution context, including parent-child relationships and command-line arguments. The file creation events provide crucial artifacts for forensic analysis and timeline reconstruction.

The dataset effectively demonstrates how legitimate Windows tools can be weaponized for malicious purposes while maintaining a low detection profile. The ETW integration (`--etw` flag) and temporary file output patterns are particularly valuable for developing behavioral detection rules.

The process access events (Sysmon EID 10) showing PowerShell accessing whoami.exe and cmd.exe processes provide additional context for understanding the broader attack simulation framework, though they're not directly related to the network sniffing technique itself.

## Detection Opportunities Present in This Data

1. **Pktmon process execution** - Monitor Security EID 4688 and Sysmon EID 1 for pktmon.exe execution, particularly with `start` and `--etw` parameters indicating packet capture initiation.

2. **ETL file creation in temp directories** - Alert on Sysmon EID 11 file creation events for `.etl` files in temporary locations (`%TEMP%`, `C:\Windows\Temp`), especially when created by pktmon.exe processes.

3. **Command-line pattern matching** - Detect the specific command structure `pktmon.exe start --etw -f [path]` followed by `pktmon.exe stop` within short time windows, indicating scripted packet capture operations.

4. **Batch command chaining** - Monitor for cmd.exe processes executing multiple commands with `&` separators that include pktmon start/stop sequences, timeout delays, and output redirection.

5. **Privilege escalation correlation** - Correlate Security EID 4703 SeLoadDriverPrivilege events with subsequent pktmon execution to identify potential privilege abuse scenarios.

6. **Process lineage analysis** - Track PowerShell → cmd.exe → pktmon.exe execution chains, particularly when PowerShell exhibits AMSI loading patterns (Sysmon EID 7) suggesting potential bypass attempts.

7. **Temporal clustering** - Detect rapid pktmon start/stop cycles with consistent timing patterns (e.g., 5-second intervals) that may indicate automated network reconnaissance activities.
