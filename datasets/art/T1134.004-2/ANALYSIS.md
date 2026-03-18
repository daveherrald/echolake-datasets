# T1134.004-2: Parent PID Spoofing — Parent PID Spoofing - Spawn from Current Process

## Technique Context

Parent PID spoofing is a defense evasion technique where attackers manipulate the parent process identifier (PPID) to hide the true ancestry of spawned processes. This technique disrupts process lineage tracking used by security tools and analysts to understand attack chains. In T1134.004-2, the technique specifically creates a new process while falsifying its parent relationship to appear as if it spawned from a different process than the actual creator.

The detection community focuses on identifying anomalous parent-child relationships, unexpected process access patterns during creation, and API calls that manipulate process creation structures. Key indicators include processes with suspicious parent relationships, unusual privilege requests during process creation, and processes spawning from unexpected parent processes given the execution context.

## What This Dataset Contains

This dataset captures a successful parent PID spoofing execution using PowerShell's `Start-ATHProcessUnderSpecificParent` function. The technique creates a new PowerShell process with command line `'-Command Start-Sleep 10'` while spoofing its parent PID.

The key evidence appears in Security event 4688 showing the spoofed process creation:
- **Creator Process**: PID 33372 (`powershell.exe`)
- **Target Process**: PID 33608 (`powershell.exe`) with command line `"powershell.exe" & {Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10' -ParentId $PID}`

Sysmon captures critical process access events (EID 10) showing the manipulation:
- Process 33372 accessing process 33608 with `GrantedAccess: 0x1FFFFF` (full process access)
- Call trace showing .NET System.Management.Automation involvement in process manipulation

The PowerShell channel contains the technique execution in script block 61afe598: `Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10' -ParentId $PID`

Security event 4703 shows privilege elevation with multiple sensitive privileges enabled, including `SeAssignPrimaryTokenPrivilege` which is required for process creation manipulation.

## What This Dataset Does Not Contain

This dataset does not contain Sysmon ProcessCreate (EID 1) events for the initial PowerShell processes due to the include-mode filtering in the sysmon-modular configuration. The Sysmon EID 1 events captured are for `whoami.exe` and the final spawned PowerShell process, but not the intermediate PowerShell processes performing the spoofing.

The dataset lacks detailed API-level telemetry showing the specific Win32 API calls (like `CreateProcess` with modified `STARTUPINFOEX` structures) used to implement the spoofing. Windows does not provide native events for these low-level process creation manipulations.

There are no network connections or external communications in this test, as the technique focuses purely on local process manipulation. The spawned process only executes `Start-Sleep 10` without any additional malicious activity.

## Assessment

This dataset provides excellent telemetry for detecting parent PID spoofing through process access patterns and privilege usage. The combination of Security 4688 events with command-line logging, Security 4703 privilege elevation events, and Sysmon 10 process access events creates a strong detection foundation.

The Security channel's complete process creation coverage compensates for the filtered Sysmon ProcessCreate events, providing full visibility into the process creation chain. The PowerShell script block logging captures the exact technique execution, making this particularly valuable for PowerShell-based spoofing detection.

The Sysmon process access events are especially valuable, as they show the specific access patterns required for process manipulation that normal parent-child relationships wouldn't exhibit.

## Detection Opportunities Present in This Data

1. **Process Access for Creation Manipulation** - Sysmon EID 10 events showing processes accessing other processes with full access rights (0x1FFFFF) during or immediately before process creation

2. **Privilege Escalation for Process Creation** - Security EID 4703 showing elevation of `SeAssignPrimaryTokenPrivilege` and other process creation privileges outside normal system operations

3. **PowerShell Process Manipulation Functions** - PowerShell EID 4104 script blocks containing functions like `Start-ATHProcessUnderSpecificParent` or similar process creation manipulation commands

4. **Anomalous Process Creation Command Lines** - Security EID 4688 events showing PowerShell processes with command lines containing process creation manipulation parameters or functions

5. **Process Tree Inconsistencies** - Correlation between Security 4688 process creation events and Sysmon process access patterns to identify manipulated parent-child relationships

6. **Rapid Process Creation with Access Patterns** - Temporal correlation of process access (Sysmon EID 10) immediately followed by process creation (Security EID 4688) from different source processes

7. **PowerShell Execution Policy Bypass with Process Manipulation** - PowerShell EID 4103 showing execution policy bypass combined with process creation functions in the same session
