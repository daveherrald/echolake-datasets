# T1082-30: System Information Discovery — BIOS Information Discovery through Registry

## Technique Context

T1082 System Information Discovery is a fundamental reconnaissance technique where adversaries collect detailed information about the victim system's hardware, software, and configuration. Within this technique, BIOS information discovery through registry queries represents a specific approach to gathering low-level hardware details that can inform attack planning, help identify virtualized environments, or assist in fingerprinting systems for targeted exploitation.

The detection community focuses heavily on registry queries to hardware-related keys, particularly `HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System`, as these locations contain sensitive system fingerprinting data including BIOS versions, hardware identifiers, and system manufacturer information. These queries are often early indicators of reconnaissance activity and can signal the beginning of a broader attack chain.

## What This Dataset Contains

This dataset captures a straightforward BIOS information discovery sequence executed through PowerShell and command-line tools. The core activity is visible in Security event 4688, showing cmd.exe execution with the command line: `"cmd.exe" /c reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v SystemBiosVersion & reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v VideoBiosVersion`.

The process chain shows PowerShell (PID 40268) spawning cmd.exe (PID 34972), which then creates two reg.exe processes (PIDs 27656 and 8020) to query the SystemBiosVersion and VideoBiosVersion registry values respectively. Sysmon EID 1 events capture all process creations with appropriate rule names including "technique_id=T1012,technique_name=Query Registry" for the reg.exe processes.

The dataset includes multiple PowerShell instances (PIDs 16856, 40268, 40684) with extensive Sysmon EID 7 image load events showing .NET runtime initialization and Windows Defender integration. Security EID 4703 shows token privilege adjustment for the PowerShell process, enabling elevated system access required for hardware registry queries.

Notably, one of the reg.exe processes (PID 8020) exits with status 0x1, indicating the VideoBiosVersion query failed, which is common in virtualized environments where video BIOS information may not be available through standard registry locations.

## What This Dataset Does Not Contain

The dataset lacks the actual output or results of the registry queries. While we can see the reg.exe processes executing and their exit codes, there's no capture of what BIOS information was successfully retrieved. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual discovery commands or their output.

There are no object access audit events (EID 4656/4658) showing the specific registry keys being accessed, as the Windows audit policy has object access disabled. This means we can detect the process execution but not the granular registry key access patterns that would provide additional forensic detail.

The dataset also doesn't contain any network communication that might indicate the gathered system information being exfiltrated, nor does it show follow-on reconnaissance activities that typically accompany BIOS discovery in real attack scenarios.

## Assessment

This dataset provides excellent baseline telemetry for detecting BIOS information discovery through registry queries. The Security 4688 events with command-line logging capture the most critical detection artifacts - the specific registry paths and values being queried. The Sysmon process creation events add valuable context with parent-child relationships and process hashes.

The presence of both successful (exit code 0x0) and failed (exit code 0x1) registry queries creates realistic detection scenarios, as registry discovery often involves probing multiple keys with varying success rates. The clear process lineage from PowerShell → cmd.exe → reg.exe provides multiple detection points along the execution chain.

However, the dataset would be stronger with object access auditing enabled to capture the actual registry key access events, and with PowerShell script block logging showing the original commands rather than just test framework artifacts.

## Detection Opportunities Present in This Data

1. **Registry Query Command Lines** - Security EID 4688 events with command lines containing "reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System" combined with BIOS-related value names (SystemBiosVersion, VideoBiosVersion)

2. **Hardware Registry Key Targeting** - Process creation events where reg.exe targets the HARDWARE\DESCRIPTION\System registry hive, particularly when querying multiple BIOS-related values in sequence

3. **PowerShell-to-Registry Chain** - Process lineage showing PowerShell spawning cmd.exe or reg.exe processes that query hardware-specific registry locations

4. **BIOS Discovery Process Patterns** - Multiple reg.exe processes created in quick succession (within seconds) targeting different BIOS-related registry values from the same parent process

5. **Failed Registry Query Correlation** - Processes with exit code 0x1 when querying VideoBiosVersion, potentially indicating virtual machine detection attempts through BIOS enumeration failures
