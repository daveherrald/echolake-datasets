# T1036.003-6: Rename Legitimate Utilities — Masquerading - non-windows exe running as windows exe

## Technique Context

T1036.003 involves adversaries renaming malicious files to masquerade as legitimate system utilities, evading detection by fooling users and security tools that rely on filename-based identification. This technique is particularly effective because many security controls use filename patterns for allow-listing or detection logic. The specific test here attempts to copy a custom executable (`T1036.003.exe`) to `svchost.exe` in the temp directory and execute it, mimicking a common Windows system process. Detection engineers typically focus on identifying processes with suspicious parent relationships, unsigned binaries masquerading as signed system tools, or executables running from unexpected locations.

## What This Dataset Contains

The dataset captures a failed masquerading attempt with clear telemetry across multiple data sources. In Security event 4688, we see PowerShell spawning with the command line `"powershell.exe" & {copy \"C:\AtomicRedTeam\atomics\T1036.003\bin\T1036.003.exe\" ($env:TEMP + \"\svchost.exe\"")...}`, revealing the technique's intent. The PowerShell script block logging in event 4104 preserves the complete attack logic: `copy "C:\AtomicRedTeam\atomics\T1036.003\bin\T1036.003.exe" ($env:TEMP + "\svchost.exe")` followed by `Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")`. However, PowerShell event 4100 shows the technique failed with "Error Message = This command cannot be run due to the error: The system cannot find the file specified" and "InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand". Sysmon captures the parent-child process relationships through events 1 (ProcessCreate) for both the whoami.exe discovery command and the PowerShell execution, along with process access events 10 showing PowerShell accessing other processes. The Security channel shows the PowerShell process exiting with status `0x80131509`, indicating an exception occurred.

## What This Dataset Does Not Contain

Critically missing is any Sysmon ProcessCreate event for the intended masqueraded `svchost.exe` process, confirming the technique failed before the malicious binary could execute. The sysmon-modular configuration's include-mode filtering wouldn't have captured a simple executable copy operation, so there's no Sysmon event 11 (FileCreate) for the actual file copy to `%TEMP%\svchost.exe`. We also lack any network connections, registry modifications, or file access events that would typically follow successful process masquerading. The dataset doesn't show whether Windows Defender blocked the file copy operation or if the source file simply didn't exist at the specified path. There's no evidence of the intended masqueraded process appearing in the process tree or making any system calls.

## Assessment

This dataset provides excellent visibility into a failed masquerading attempt through complementary data sources. The PowerShell script block logging (4104) and command-line auditing (4688) offer complete reconstruction of the attack methodology, while the error logging (4100) confirms the failure point. The process creation and access events in both Sysmon and Security channels provide solid process ancestry tracking. For detection engineering, this represents a high-fidelity capture of technique preparation and execution attempt, even though the actual masquerading didn't succeed. The data would be stronger with file operation visibility (Sysmon event 11) to show copy attempts and Windows Defender logs to understand why the technique failed.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Event 4104 contains the complete attack script showing file copy operations to rename executables with system process names like `svchost.exe`

2. **Command Line Masquerading Patterns** - Security event 4688 command line contains `copy` operations moving files from suspicious paths (`AtomicRedTeam`) to `%TEMP%` with system process names

3. **PowerShell Error Correlation** - Event 4100 "InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand" combined with "system cannot find the file specified" indicates failed process execution attempts

4. **Suspicious Process Ancestry** - Sysmon event 1 shows PowerShell spawning from another PowerShell process with masquerading-related command lines in the parent process

5. **Temp Directory Execution Attempts** - PowerShell trying to execute processes from `%TEMP%` directory with system process names like `svchost.exe`

6. **File Copy to System Process Names** - Script blocks showing copy operations where the destination filename matches known system processes (`svchost.exe`)

7. **Process Exit Code Analysis** - Security event 4689 showing PowerShell exit with status `0x80131509` indicating .NET exceptions during malicious activity

8. **Start-Process Cmdlet with Suspicious Paths** - PowerShell script blocks containing `Start-Process` cmdlet targeting executables in temporary directories with system process names
