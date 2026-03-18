# T1003-5: OS Credential Dumping — Retrieve Microsoft IIS Service Account Credentials Using AppCmd (using config)

## Technique Context

T1003.005 focuses on retrieving cached credentials from Microsoft Internet Information Services (IIS) using the appcmd.exe utility. IIS application pools can be configured to run under specific service accounts, and these account names (though not passwords) are stored in IIS configuration files. Attackers with administrative access can use appcmd.exe to enumerate application pool configurations and identify service accounts that might be targeted for further credential attacks or lateral movement.

The technique is particularly valuable to attackers because IIS service accounts often have elevated privileges needed to access databases, file shares, and other network resources. While appcmd.exe doesn't directly extract passwords, it reveals account names that can be targeted through other credential dumping techniques or password attacks. The detection community focuses on monitoring appcmd.exe execution patterns, especially when used with configuration enumeration switches like `/config`.

## What This Dataset Contains

This dataset captures a straightforward execution of the IIS credential enumeration technique. The core activity is visible in Security event 4688, which shows PowerShell spawning with the command line `"powershell.exe" & {C:\Windows\System32\inetsrv\appcmd.exe list apppool /config}`. This command attempts to list all IIS application pools with their configuration details, which would expose any configured service account names.

PowerShell script block logging in event 4104 captures the actual command execution: `& {C:\Windows\System32\inetsrv\appcmd.exe list apppool /config}` and the simpler form `{C:\Windows\System32\inetsrv\appcmd.exe list apppool /config}`. The PowerShell channel shows typical test framework boilerplate with Set-ExecutionPolicy Bypass commands.

Sysmon provides comprehensive process creation telemetry, with event ID 1 showing both the `whoami.exe` execution (Process ID 6504) for user discovery and the PowerShell process (Process ID 6732) executing the appcmd command. The process chain shows the parent PowerShell (PID 5592) spawning the child PowerShell that executes the technique.

## What This Dataset Does Not Contain

The dataset lacks the actual appcmd.exe process creation event, likely because the sysmon-modular configuration uses include-mode filtering for ProcessCreate events, and appcmd.exe may not match the known-suspicious patterns. This is a significant gap since direct appcmd.exe execution would be the most specific indicator of this technique.

There are no network connections to external IIS management tools or configuration files being accessed, suggesting the technique executed but may not have found active IIS configurations to enumerate. The dataset doesn't contain any file access events showing interaction with IIS configuration files like applicationHost.config, which would be expected if IIS were installed and configured.

The absence of additional credential-related artifacts (no LSASS access, no registry credential stores being queried) indicates this was purely a reconnaissance attempt rather than a full credential extraction operation.

## Assessment

The dataset provides moderate utility for detection engineering, capturing the PowerShell wrapper and command-line evidence clearly through Security 4688 and PowerShell script block logging. However, the missing appcmd.exe process creation significantly limits its value for building comprehensive detections. The Security channel with command-line auditing proves more reliable here than Sysmon's filtered ProcessCreate events.

For organizations primarily concerned with PowerShell-based execution of appcmd, this data is quite useful. However, direct appcmd.exe execution (which would bypass PowerShell entirely) wouldn't be captured with the same fidelity, making this dataset incomplete for understanding the full attack surface of T1003.005.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: Security 4688 events showing PowerShell processes with command lines containing `appcmd.exe list apppool /config` or similar IIS configuration enumeration commands.

2. **Script Block Content Filtering**: PowerShell 4104 events containing script blocks that invoke appcmd.exe with configuration listing parameters (`/config`, `list apppool`).

3. **Process Chain Analysis**: Parent-child relationships where PowerShell spawns additional PowerShell processes specifically to execute appcmd commands, as shown in the Sysmon process tree.

4. **Command Pattern Detection**: Regular expressions matching appcmd.exe invocation patterns focused on configuration enumeration, particularly when combined with `/config` flags.

5. **User Context Correlation**: Execution of appcmd configuration commands under SYSTEM or administrative accounts, especially when preceded by user discovery commands like whoami.exe.

6. **PowerShell Module Loading**: Sysmon 7 events showing System.Management.Automation.dll loading in PowerShell processes that subsequently execute IIS-related commands.
