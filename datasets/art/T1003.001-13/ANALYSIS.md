# T1003.001-13: LSASS Memory — Dump LSASS.exe using lolbin rdrleakdiag.exe

## Technique Context

T1003.001 LSASS Memory is a credential access technique where adversaries dump the memory of the Local Security Authority Subsystem Service (LSASS) process to extract plaintext credentials, password hashes, and Kerberos tickets. The LSASS process stores authentication credentials for logged-in users, making it a high-value target for privilege escalation and lateral movement.

This specific test uses `rdrleakdiag.exe`, a lesser-known Windows diagnostic tool that can create memory dumps - making it a "Living off the Land Binary" (LOLBin). Unlike more commonly monitored tools like `procdump.exe` or `comsvcs.dll`, `rdrleakdiag.exe` may evade detection due to its legitimate diagnostic purpose and lower profile in security tooling.

The detection community focuses heavily on LSASS access patterns, process creation of dumping tools, file creation of dump artifacts, and privilege escalation events that enable LSASS access.

## What This Dataset Contains

This dataset captures a successful execution attempt of the rdrleakdiag technique with the following key artifacts:

**Process Creation Chain**: Security 4688 events show the full PowerShell command line executing the LSASS dump: `"powershell.exe" & {if (Test-Path -Path \"$env:SystemRoot\System32\rdrleakdiag.exe\") { $binary_path = \"$env:SystemRoot\System32\rdrleakdiag.exe\" } ... & $binary_path /p $lsass_pid /o $env:TEMP\t1003.001-13-rdrleakdiag /fullmemdmp /wait 1`

**System Privileges**: Security 4703 shows the parent PowerShell process (PID 6272) enabling multiple high-privilege tokens including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` - privileges commonly required for LSASS access.

**Process Access Telemetry**: Sysmon EID 10 events capture PowerShell processes accessing both `whoami.exe` (PID 6176) and another PowerShell process (PID 7052) with `GrantedAccess: 0x1FFFFF` (full access rights), indicating the technique's process enumeration and interaction patterns.

**Execution Failure**: The second PowerShell process (PID 7052) exits with status `0x1`, indicating the rdrleakdiag execution failed, likely due to Windows Defender intervention.

**LOLBin Detection**: Sysmon EID 1 captures the child PowerShell process (PID 7052) with the complete attack command line, tagged with `technique_id=T1083,technique_name=File and Directory Discovery`.

## What This Dataset Does Not Contain

**No rdrleakdiag.exe Process Creation**: The sysmon-modular config uses include-mode filtering for ProcessCreate events, and `rdrleakdiag.exe` is not in the suspicious patterns list, so no Sysmon EID 1 event was generated for the actual LOLBin execution.

**No LSASS Access Events**: Despite the process access events showing high privileges, there are no Sysmon EID 10 events showing direct access to the LSASS process (typically PID 600-800 range), suggesting Windows Defender blocked the access attempt before it reached LSASS.

**No File Creation for Dump**: No Sysmon EID 11 events show creation of `.dmp` files in `C:\Windows\TEMP\t1003.001-13-rdrleakdiag\`, confirming the dump operation was prevented.

**No Network Activity**: No Sysmon network events suggest the failed dump was not exfiltrated.

**Limited PowerShell Script Block Content**: PowerShell 4104 events contain only test framework boilerplate (`Set-StrictMode`, error handling scriptblocks) rather than the actual malicious command content, though the full command line is preserved in Security 4688.

## Assessment

This dataset provides excellent telemetry for detecting LSASS dumping attempts using LOLBins, even when the technique is blocked by endpoint protection. The Security channel's command-line logging proves invaluable here, capturing the complete attack syntax that would be missed by Sysmon's filtered ProcessCreate events. The privilege escalation events (Security 4703) and process access patterns (Sysmon 10) offer additional detection opportunities.

However, the dataset's value is somewhat limited by the successful blocking - we don't see the complete attack chain including actual LSASS access or dump file creation. For building detections of successful LSASS dumps, additional data sources showing unblocked executions would be needed.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Command Lines**: Security 4688 events containing `rdrleakdiag.exe` with `/fullmemdmp` parameters and LSASS PID enumeration patterns (`get-process lsass |select -expand id`)

2. **High-Privilege Token Enabling**: Security 4703 events showing PowerShell processes enabling `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` simultaneously

3. **Process Access with Full Rights**: Sysmon EID 10 events showing processes accessing others with `GrantedAccess: 0x1FFFFF` from PowerShell, particularly when combined with LOLBin command lines

4. **LOLBin File Path Testing**: Command lines containing `Test-Path` operations against diagnostic tools in `System32` and `SysWOW64` directories, especially when combined with process enumeration

5. **Temp Directory Structure Creation**: File creation events for structured temporary directories (`t1003.001-*` patterns) in system temp locations, indicating preparation for credential dumping operations

6. **Failed Process Exit Codes**: Security 4689 events showing PowerShell child processes exiting with status `0x1` when parent processes contain LSASS dumping command lines, potentially indicating blocked attack attempts
