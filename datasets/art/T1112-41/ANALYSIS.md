# T1112-41: Modify Registry — Ursnif Malware Registry Key Creation

## Technique Context

T1112 Modify Registry is a fundamental technique used by adversaries to establish persistence, evade defenses, or alter system configurations. This specific test simulates Ursnif malware behavior by creating a suspicious registry key under `HKCU\Software\AppDataLow\Software\Microsoft\` with a GUID-like name and binary data. Ursnif is a banking trojan that often stores configuration data and persistence mechanisms in the registry using obfuscated keys to blend in with legitimate Microsoft entries.

The detection community focuses on monitoring registry modifications, particularly those creating new keys in user hives with suspicious characteristics like random GUIDs, binary data in unexpected locations, or patterns matching known malware families. Registry monitoring via Sysmon Event ID 13 (RegistryEvent) and 12 (RegistryEvent Object create/delete) are primary detection vectors, along with process lineage analysis when registry utilities are spawned.

## What This Dataset Contains

This dataset captures a complete execution chain for registry modification using cmd.exe and reg.exe:

**Process Chain:**
- PowerShell (PID 25288) → cmd.exe (PID 21336) → reg.exe (PID 34740)
- Security Event 4688 shows cmd.exe execution: `"cmd.exe" /c reg add HKCU\Software\AppDataLow\Software\Microsoft\3A861D62-51E0-15700F2219A4 /v comsxRes /t REG_BINARY /d 72656463616e617279 /f`
- Security Event 4688 shows reg.exe execution: `reg add HKCU\Software\AppDataLow\Software\Microsoft\3A861D62-51E0-15700F2219A4 /v comsxRes /t REG_BINARY /d 72656463616e617279 /f`

**Sysmon Coverage:**
- Sysmon Event ID 1 (Process Create) for cmd.exe and reg.exe with full command lines
- Sysmon Event ID 10 (Process Access) showing PowerShell accessing both child processes with 0x1FFFFF access rights
- Multiple Sysmon Event ID 7 (Image Load) events for PowerShell .NET runtime components

**Registry Operation Details:**
- Target key: `HKCU\Software\AppDataLow\Software\Microsoft\3A861D62-51E0-15700F2219A4`
- Value name: `comsxRes`
- Data type: `REG_BINARY`
- Data: `72656463616e617279` (hex encoding of "redcanary")

## What This Dataset Does Not Contain

**Missing Critical Registry Events:** The most significant gap is the absence of Sysmon Event ID 12/13 (Registry Object Create/Registry Value Set) events that would directly capture the registry modification. This suggests the sysmon-modular configuration may have filtered these events or they were not generated due to an error condition.

**No Error Telemetry:** All processes show exit code 0x0, indicating successful completion, but we lack confirmation that the registry key was actually created since we don't see the corresponding registry modification events.

**Limited PowerShell Context:** The PowerShell script block logging only captures test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual command that spawned the child processes.

## Assessment

This dataset provides excellent process execution telemetry for registry modification attempts but lacks the critical registry modification events that would confirm the technique's success. The Security and Sysmon Event ID 1 coverage is comprehensive, capturing the complete process chain with full command lines that clearly show the malicious intent. The hex-encoded data pattern and suspicious registry path are well-preserved in the command lines.

However, without Sysmon Event ID 12/13 coverage, this dataset is incomplete for comprehensive registry monitoring detection development. The process-based detections are strong, but registry-centric detection logic cannot be fully validated.

## Detection Opportunities Present in This Data

1. **Command Line Pattern Detection** - Alert on reg.exe with `REG_BINARY` type and hex-encoded data patterns, especially with paths containing Microsoft subdirectories and GUID-like strings

2. **Suspicious Registry Path Structure** - Detect registry operations targeting `HKCU\Software\AppDataLow\Software\Microsoft\` followed by GUID patterns (format: XXXXXXXX-XXXX-XXXXXXXXXXXX)

3. **Process Chain Analysis** - Monitor for PowerShell spawning cmd.exe which spawns reg.exe, particularly when the command contains binary data operations

4. **Binary Data Encoding Detection** - Flag reg.exe operations with REG_BINARY type where data appears to be hex-encoded ASCII strings

5. **Ursnif Registry Behavior** - Specific detection for registry keys under Microsoft paths with value names like "comsxRes" and binary data characteristics

6. **Process Access Pattern** - Alert on PowerShell processes accessing registry utilities with full access rights (0x1FFFFF) as seen in the Sysmon Event ID 10 events

7. **Execution Context Analysis** - Detect registry modification attempts executed via cmd.exe /c patterns from scripting engines, especially when creating keys with randomized identifiers
