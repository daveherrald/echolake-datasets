# T1018-9: Remote System Discovery — Remote System Discovery - adidnsdump

## Technique Context

T1018 Remote System Discovery is a discovery technique where adversaries attempt to identify remote systems on a network through various enumeration methods. The adidnsdump tool specifically targets Active Directory Integrated DNS (ADIDNS) records to discover systems and services in an AD environment. This Python-based tool queries domain controllers directly to extract DNS records that may reveal hostnames, IP addresses, and service records that aren't typically visible through standard DNS queries.

Detection communities focus heavily on monitoring DNS enumeration activities, especially those targeting domain controllers with unusual query patterns or using non-standard tools. The technique is particularly concerning because ADIDNS records can reveal internal network topology, service locations, and system naming conventions that assist in lateral movement planning.

## What This Dataset Contains

This dataset captures a failed execution of adidnsdump, revealing the telemetry patterns when the tool encounters authentication or network connectivity issues. The core execution shows in Security event 4688: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1018\Scripts\adidnsdump" -u domain\user -p password --print-zones 192.168.1.1` with exit status 0x1 (failure).

The process chain demonstrates the typical PowerShell test framework execution: PowerShell (PID 7236) spawns cmd.exe (PID 5584) which attempts to execute the adidnsdump Python script from a virtual environment at `C:\AtomicRedTeam\atomics\..\ExternalPayloads\venv_t1018\Scripts\adidnsdump`. The command line includes hardcoded credentials (`-u domain\user -p password`) and targets IP 192.168.1.1 with the `--print-zones` flag.

Sysmon captures extensive process creation details in event ID 1, showing the full command line with credentials in plaintext. Process access events (EID 10) show PowerShell accessing both whoami.exe and cmd.exe with 0x1FFFFF access rights. The PowerShell events contain only test framework boilerplate with Set-StrictMode and Set-ExecutionPolicy Bypass commands.

## What This Dataset Does Not Contain

The dataset lacks successful DNS enumeration telemetry because the adidnsdump execution failed (exit code 0x1). No DNS query events, network connections, or LDAP traffic appear in the logs, indicating the tool never successfully connected to the target domain controller. The failure likely stems from invalid credentials or network connectivity issues to 192.168.1.1.

Missing are Sysmon DNS events (EID 22) that would typically show the tool's DNS queries, network connection events (EID 3) that would reveal connections to domain controllers, and any file creation events showing enumeration results being written to disk. The tool's Python subprocess execution is also not captured in process creation events, suggesting it failed before reaching the main enumeration logic.

## Assessment

This dataset provides limited value for detecting successful adidnsdump executions but offers excellent insight into reconnaissance attempt patterns and failure scenarios. The process creation telemetry clearly captures the tool invocation with full command lines, including credential parameters that would be highly valuable for incident response. The failure pattern (exit code 0x1) demonstrates how authentication or connectivity failures present in logs.

The telemetry quality for the attempt phase is strong across both Security 4688 and Sysmon EID 1 events, providing redundant coverage of the malicious command execution. However, the lack of network-level telemetry limits its utility for understanding the tool's DNS enumeration behaviors when functioning properly.

## Detection Opportunities Present in This Data

1. **Command Line Detection**: Security 4688 and Sysmon EID 1 events capture `adidnsdump` execution with full command line arguments including credentials and target IP addresses.

2. **Process Chain Analysis**: PowerShell spawning cmd.exe which executes Python scripts from AtomicRedTeam directories indicates potential red team tool usage.

3. **Credential Exposure**: Plaintext credentials visible in command line arguments (`-u domain\user -p password`) across multiple event types.

4. **Tool Path Detection**: Execution from `ExternalPayloads\venv_t1018\Scripts\` path structure indicates organized red team toolkit deployment.

5. **Process Access Monitoring**: Sysmon EID 10 events show PowerShell accessing spawned processes with full access rights (0x1FFFFF), indicating potential process manipulation.

6. **Exit Code Analysis**: Security 4689 events with exit status 0x1 indicate failed reconnaissance attempts that may warrant investigation.

7. **Virtual Environment Detection**: Python virtual environment activation patterns in AtomicRedTeam directory structure suggest automated testing framework usage.
