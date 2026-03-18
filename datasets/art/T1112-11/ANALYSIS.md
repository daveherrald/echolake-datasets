# T1112-11: Modify Registry — Disable Windows CMD application

## Technique Context

T1112 (Modify Registry) is a fundamental defense evasion and persistence technique where adversaries alter Windows registry keys to modify system behavior, disable security controls, or maintain persistence. The specific test here attempts to disable the Windows Command Prompt (cmd.exe) by creating the `DisableCMD` registry value under `HKCU:\Software\Policies\Microsoft\Windows\System`. This is a classic administrative restriction that organizations use to prevent users from accessing the command line, and attackers may leverage it to limit incident response capabilities or create the appearance of legitimate administrative policy.

The detection community focuses heavily on registry modifications targeting security controls, administrative restrictions, and persistence locations. PowerShell-based registry manipulation is particularly scrutinized since it's commonly used by both administrators and attackers. Key detection points include monitoring for registry writes to policy locations, especially those that disable system tools or modify security settings.

## What This Dataset Contains

This dataset captures a failed attempt to disable CMD through registry modification. The core telemetry shows:

**Process execution chain**: Security event 4688 reveals the command line `"powershell.exe" & {New-ItemProperty -Path \"HKCU:\Software\Policies\Microsoft\Windows\System\" -Name DisableCMD -Value 1}` executed by a PowerShell process (PID 8756) spawning another PowerShell process (PID 15228).

**PowerShell script block logging**: Event 4104 captures the actual PowerShell command `New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name DisableCMD -Value 1` along with the error condition.

**Command failure telemetry**: PowerShell event 4103 shows the `New-ItemProperty` cmdlet execution with a `NonTerminatingError` stating "Cannot find path 'HKCU:\Software\Policies\Microsoft\Windows\System' because it does not exist."

**Sysmon process creation**: Event 1 captures both the whoami.exe execution (PID 16616) and the PowerShell spawn (PID 15228) with full command lines and process relationships.

**System privilege context**: All execution occurs under `NT AUTHORITY\SYSTEM` with Security event 4703 showing extensive privilege assignment including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege`.

## What This Dataset Does Not Contain

**No successful registry modification**: The technique fails because the target registry path doesn't exist, so there are no registry write events or Sysmon Event 13 (RegistryEvent) showing the actual creation of the `DisableCMD` value.

**No Sysmon ProcessCreate for initial PowerShell**: The parent PowerShell process (PID 8756) lacks a corresponding Sysmon Event 1, likely filtered out by the sysmon-modular include-mode configuration since it doesn't match suspicious process patterns.

**No registry key creation**: The command attempts to create a registry value but not the parent key structure, and Windows doesn't automatically create missing intermediate keys, causing the operation to fail.

**Limited PowerShell module logging**: While script block logging captures the command, there's no evidence of module imports or additional PowerShell activity beyond the basic registry operation attempt.

## Assessment

This dataset provides excellent telemetry for detecting attempted registry-based defense evasion, even when the technique fails. The combination of Security 4688 command-line logging, PowerShell script block logging, and Sysmon process creation events creates multiple detection opportunities. The failure condition actually enhances the dataset's value by showing how defensive tools can capture attack attempts that don't succeed due to environmental conditions.

The PowerShell logging is particularly strong, capturing both the command invocation (4103) and the script block content (4104), along with the specific error condition. Security event logging provides full command-line visibility and process relationships. The privilege assignment logging (4703) adds context about the execution environment's elevated rights.

## Detection Opportunities Present in This Data

1. **PowerShell registry policy manipulation**: Event 4104 script block containing `New-ItemProperty` targeting `Software\Policies\Microsoft\Windows\System` with `DisableCMD` parameter

2. **Command-line registry modification attempts**: Security 4688 process creation with command line containing `New-ItemProperty`, `HKCU:\Software\Policies`, and `DisableCMD` keywords

3. **PowerShell cmdlet execution patterns**: Event 4103 showing `New-ItemProperty` cmdlet with policy-related registry paths as parameters

4. **Failed registry operations**: PowerShell error events indicating registry path not found, which may indicate reconnaissance or misconfigured attack tools

5. **Elevated PowerShell spawning child PowerShell**: Sysmon Event 1 showing PowerShell process (PID 8756) creating another PowerShell process (PID 15228) with registry manipulation parameters

6. **System-level privilege assignment**: Security 4703 showing extensive privilege grants including backup/restore and security privileges, which may precede registry manipulation attempts

7. **PowerShell execution with embedded registry commands**: Process command lines containing both PowerShell execution and inline registry modification syntax (`& {New-ItemProperty...}`)
