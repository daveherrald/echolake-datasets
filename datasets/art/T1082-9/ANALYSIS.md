# T1082-9: System Information Discovery — Windows MachineGUID Discovery

## Technique Context

T1082 (System Information Discovery) involves adversaries gathering information about the victim system's configuration, hardware, and operating environment. The Windows MachineGUID is a unique identifier stored in the registry at `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid` that persists across OS installations and is commonly used for system fingerprinting, licensing validation, and tracking. Attackers often query this value during reconnaissance to uniquely identify compromised systems, correlate attacks across multiple incidents, or validate system changes. Detection engineers focus on monitoring registry queries to this specific key, as legitimate software rarely accesses the MachineGUID directly, making such queries a strong indicator of discovery activity.

## What This Dataset Contains

This dataset captures a PowerShell-based system discovery technique that queries the Windows MachineGUID through registry access. The attack chain shows:

**Process execution chain**: PowerShell spawns cmd.exe which launches reg.exe to query the registry:
- Security 4688: `"cmd.exe" /c REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid`
- Security 4688: `REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid`

**Sysmon process creation events** capture the key tools involved:
- Sysmon 1: whoami.exe execution for user discovery (technique T1033)
- Sysmon 1: cmd.exe with the registry query command (technique T1059.003)
- Sysmon 1: reg.exe execution targeting the MachineGuid value (technique T1012)

**PowerShell logging** shows only execution policy bypass boilerplate (Set-ExecutionPolicy), with no script block content indicating the registry query was likely executed via command-line parameters rather than embedded scripts.

## What This Dataset Does Not Contain

The dataset lacks several potentially valuable detection artifacts. There are no Sysmon registry access events (EID 12/13) showing the actual registry read operation, likely due to the sysmon-modular configuration not monitoring registry access by default. Windows Security event logs don't include registry access auditing (Object Access audit policy disabled). The registry query output containing the actual MachineGUID value is not captured in any log source. Additionally, there's no network activity showing potential exfiltration of the discovered information, suggesting this was purely a local discovery operation.

## Assessment

This dataset provides good coverage of process-level telemetry for MachineGUID discovery but limited visibility into the actual registry interaction. The Security 4688 events with command-line logging offer the strongest detection opportunity, clearly showing the registry query intent. Sysmon ProcessCreate events complement this with additional process metadata and parent-child relationships. However, the absence of registry access events means detection logic must rely on process command-lines rather than direct registry monitoring. For detection engineering, this represents a realistic scenario where command-line analysis becomes the primary detection vector for registry-based discovery techniques.

## Detection Opportunities Present in This Data

1. **Registry query command detection** - Security 4688 events containing `REG QUERY` targeting `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography` with `/v MachineGuid` parameter

2. **Process chain analysis** - Sysmon 1 events showing PowerShell → cmd.exe → reg.exe execution sequence focused on system discovery

3. **Discovery technique correlation** - Multiple Sysmon 1 events showing both whoami.exe (T1033) and reg.exe MachineGuid queries occurring in close temporal proximity

4. **Command-line pattern matching** - Security 4688 process creation events with CommandLine field containing specific registry path and MachineGuid value name

5. **Parent process context** - Sysmon 1 events showing reg.exe spawned from cmd.exe with discovery-related command arguments, indicating scripted reconnaissance activity
