# T1021.001-4: Remote Desktop Protocol — Disable NLA for RDP via Command Prompt

## Technique Context

T1021.001 (Remote Desktop Protocol) is a lateral movement technique where attackers use RDP to move between systems in a network. Network Level Authentication (NLA) is a security feature that requires users to authenticate before establishing a full RDP session, providing protection against certain attacks and reducing server load. Disabling NLA weakens RDP security by allowing unauthenticated connections to proceed further in the handshake process.

The detection community focuses on registry modifications to RDP configuration keys, particularly changes to the `UserAuthentication` value in the Terminal Server registry path. This technique is commonly used by attackers to ease lateral movement by reducing authentication barriers, though it requires administrative privileges to modify the registry. Security teams often monitor for both the registry changes themselves and the command-line patterns used to implement them.

## What This Dataset Contains

This dataset captures a successful execution of disabling NLA through command-line registry modification. The key evidence includes:

**Process Chain**: PowerShell spawns `cmd.exe` which then spawns `reg.exe` to perform the registry modification:
- Security 4688: `"cmd.exe" /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`
- Security 4688: `reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f`

**Sysmon Process Creation Events**: 
- EID 1: cmd.exe with full command line showing the registry modification
- EID 1: reg.exe with the specific registry path and value being set to 0 (disabled)

**Process Access Events**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe and cmd.exe processes with full access rights (0x1FFFFF), indicating process monitoring or interaction.

All processes run under NT AUTHORITY\SYSTEM context and exit cleanly with status 0x0, indicating successful execution.

## What This Dataset Does Not Contain

This dataset does not contain the actual registry modification events. Windows registry auditing is not enabled in the audit policy configuration, so Security event ID 4657 (registry value modification) events are not present. This is a significant gap since the registry change is the primary impact of this technique.

The dataset also lacks any evidence of the RDP service responding to the configuration change or actual RDP connection attempts that would demonstrate the disabled NLA in action. Additionally, there are no Windows Defender alerts or blocking actions, suggesting the technique executed without endpoint protection interference.

No Sysmon EID 13 (RegistryEvent - Value Set) events are present, likely due to the sysmon-modular configuration not monitoring this specific registry path or the events being filtered out.

## Assessment

This dataset provides good visibility into the command-line execution patterns for disabling NLA but lacks the registry telemetry that would show the actual configuration change taking place. The Security 4688 events with full command-line logging are excellent for detection purposes, capturing the exact registry path, value name, and data being modified.

The process creation telemetry is comprehensive and would support detection rules based on command-line patterns. However, the absence of registry modification events significantly limits the ability to detect this technique if attackers use alternative methods (PowerShell registry cmdlets, direct API calls, etc.) that don't rely on reg.exe.

The dataset would be much stronger with registry auditing enabled or Sysmon registry monitoring configured to capture the Terminal Server registry path modifications.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security 4688 events containing `reg add` with the specific Terminal Server registry path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` and `UserAuthentication` value

2. **Process chain analysis** - PowerShell spawning cmd.exe which spawns reg.exe, particularly when the reg.exe command targets RDP configuration registry keys

3. **Registry tool usage** - Sysmon EID 1 events for reg.exe execution with command lines containing Terminal Server configuration paths

4. **Specific value targeting** - Command lines setting `UserAuthentication` to value `0` in the RDP-Tcp configuration, which specifically disables NLA

5. **Administrative context detection** - Registry modifications to system-level RDP configuration requiring SYSTEM or administrative privileges, correlating with the execution context shown in the events
