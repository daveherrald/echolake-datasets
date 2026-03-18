# T1112-80: Modify Registry — Modify UseTPMKey Registry entry

## Technique Context

T1112 (Modify Registry) is a fundamental technique used by adversaries to maintain persistence, evade defenses, and alter system behavior by modifying Windows registry entries. Registry modification is one of the most common post-compromise activities, as the registry controls virtually every aspect of Windows system operation. The detection community focuses heavily on monitoring registry changes to sensitive keys, particularly those related to security policies, startup programs, and system configuration.

This specific test targets the `UseTPMKey` registry value under `HKLM\SOFTWARE\Policies\Microsoft\FVE`, which controls BitLocker's Trusted Platform Module (TPM) key usage behavior. Modifying this value can affect disk encryption policies and potentially weaken security protections. Adversaries commonly manipulate such policy-related registry keys to disable security features or create persistence mechanisms.

## What This Dataset Contains

This dataset captures a clean registry modification executed through PowerShell spawning cmd.exe, which then invokes reg.exe. The primary evidence includes:

**Process Chain (Security 4688 & Sysmon EID 1):**
- PowerShell → cmd.exe → reg.exe
- Command line: `reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKey /t REG_DWORD /d 2 /f`
- All processes running as NT AUTHORITY\SYSTEM with full privileges

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF)
- Call traces showing .NET framework involvement in process interaction

**Security Token Adjustments (Security 4703):**
- PowerShell enabling extensive system privileges including SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege

**Additional Artifacts:**
- Named pipe creation for PowerShell host communication
- .NET assembly loading indicative of PowerShell execution
- Windows Defender DLL loading showing real-time protection engagement

## What This Dataset Does Not Contain

Critically missing from this dataset is the actual registry modification event. Despite the reg.exe command executing successfully (exit code 0x0), there are no:

- Sysmon EID 13 (Registry value set) events
- Sysmon EID 12 (Registry object added) events  
- Any registry-specific telemetry

This absence is likely due to the sysmon-modular configuration filtering registry events for this particular key path. The configuration may not include monitoring for the `HKLM\SOFTWARE\Policies\Microsoft\FVE` branch, or registry monitoring may be disabled entirely to reduce log volume. This represents a significant gap in visibility for registry-based attacks.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) without capturing the actual PowerShell commands that initiated the registry modification.

## Assessment

This dataset demonstrates a fundamental limitation in detection coverage for registry modifications. While it excellently captures the process execution chain and provides rich context about the command executed, the absence of registry modification telemetry severely limits its utility for detecting this technique class. 

The process-level telemetry is comprehensive and would support detection of suspicious reg.exe usage patterns, but defenders relying solely on this data would miss direct registry modifications performed through other means (PowerShell registry cmdlets, .NET APIs, direct Windows API calls). For a technique as fundamental as T1112, this represents a significant blind spot.

The dataset would be significantly stronger with Sysmon registry monitoring enabled for policy-related registry keys, as these are high-value targets for adversaries seeking to modify security configurations.

## Detection Opportunities Present in This Data

1. **reg.exe execution with policy modification arguments** — Monitor Security 4688 events for reg.exe processes with command lines targeting `HKLM\SOFTWARE\Policies\*` paths

2. **PowerShell spawning system administration tools** — Alert on PowerShell processes creating cmd.exe or reg.exe children, particularly when running as SYSTEM

3. **High-privilege process accessing registry tools** — Correlate Security 4703 privilege escalation events with subsequent reg.exe execution within short time windows

4. **Cross-process access to registry manipulation tools** — Use Sysmon EID 10 events showing PowerShell accessing cmd.exe/reg.exe with full access rights as an indicator of potential automation

5. **BitLocker policy modification detection** — Specifically monitor for reg.exe command lines containing "FVE" (Full Volume Encryption) or "UseTPMKey" parameters, as these target critical disk encryption settings

6. **System-level registry modifications** — Flag any registry modification attempts targeting `HKLM\SOFTWARE\Policies\Microsoft\*` paths, as these control security-relevant group policy settings
