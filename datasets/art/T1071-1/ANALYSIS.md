# T1071-1: Application Layer Protocol — Telnet C2

## Technique Context

T1071 Application Layer Protocol represents adversary use of legitimate application-layer protocols for command and control communications. Subtype T1071.001 specifically covers web protocols, though this test appears to simulate a telnet-based C2 channel. Adversaries leverage these protocols because they blend with normal network traffic, often bypass basic network filtering, and can traverse firewalls that allow standard application protocols.

The detection community focuses on identifying suspicious application protocol usage patterns: connections to known-bad infrastructure, unusual traffic volumes, protocol anomalies, and processes making unexpected network connections. For telnet specifically, outbound connections from non-administrative tools or connections to non-standard ports warrant investigation.

## What This Dataset Contains

This dataset captures the execution of a Python-based telnet client attempting to connect to localhost port 23. The process chain shows PowerShell launching the telnet client:

Security 4688 events show the process execution: `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1071\bin\telnet_client.exe 127.0.0.1 --port 23}` followed by the actual telnet client execution with command line `"C:\AtomicRedTeam\atomics\T1071\bin\telnet_client.exe" 127.0.0.1 --port 23`.

Sysmon EID 1 captures the telnet_client.exe process creation with ProcessId 15688. The client appears to be a PyInstaller-packaged Python application, as evidenced by extensive EID 11 file creation events showing extraction to `C:\Windows\Temp\_MEI156882\` of Python runtime components, DLLs, and dependencies like `python311.dll`, OpenSSL libraries (`libssl-1_1.dll`, `libcrypto-1_1.dll`), and various Python modules.

Multiple Sysmon EID 7 events show DLL loading for the Python runtime and networking components. PowerShell script block logging (EID 4104) captures the execution command: `& {C:\AtomicRedTeam\atomics\T1071\bin\telnet_client.exe 127.0.0.1 --port 23}`.

Both telnet_client.exe processes terminate with exit status 0x1, indicating connection failure - expected since no telnet server was listening on localhost:23.

## What This Dataset Does Not Contain

This dataset lacks the most critical telemetry for T1071 detection: network connection events. Despite Sysmon being configured for network monitoring, no EID 3 (Network Connect) events appear, likely because the connection attempts failed immediately. This significantly limits the dataset's utility for network-based C2 detection.

DNS query events (if any occurred) are not present. The technique attempted localhost connection, so external DNS resolution wouldn't be expected, but this limits demonstration of DNS-based detection opportunities.

No firewall logs or network flow data supplement the endpoint telemetry. The failed connection means no actual C2 communication telemetry is captured - no protocol analysis, traffic patterns, or payload inspection opportunities.

## Assessment

This dataset provides good process execution telemetry but falls short for comprehensive T1071 detection development due to the failed network connections. The process creation and file system artifacts are well-captured through Security 4688 and Sysmon events. The PyInstaller unpacking behavior creates substantial file system noise that could mask or complicate detection.

For application layer protocol detection, successful network connections are essential. This dataset would benefit from either a listening telnet server to enable successful connections or modification to attempt connections to external hosts that might generate different failure modes and network telemetry.

The telemetry is strongest for detecting suspicious process execution patterns and file system staging behaviors common to packaged offensive tools.

## Detection Opportunities Present in This Data

1. **Suspicious telnet client execution** - Process creation of telnet clients from PowerShell, especially with non-standard command line arguments like `--port 23`

2. **PyInstaller artifact staging** - Mass file creation in Windows temp directories (`_MEI*` patterns) indicating unpacked Python executables, which often indicates offensive tooling

3. **Python runtime loading from temp directories** - DLL loads of `python311.dll` and associated Python modules from temporary extraction paths rather than standard installation directories

4. **PowerShell script block analysis** - Direct command execution patterns in EID 4104 showing telnet client invocation with specific IP addresses and ports

5. **Process relationship analysis** - PowerShell spawning network client tools, particularly when the parent PowerShell process lacks typical interactive session indicators

6. **Temporary file cleanup patterns** - Monitoring for cleanup of `_MEI*` directories which often indicates completion of packaged tool execution

7. **Failed process exit codes** - Exit status 0x1 from network client tools may indicate blocked or failed C2 attempts worth investigating
