# T1003-4: OS Credential Dumping — Retrieve Microsoft IIS Service Account Credentials Using AppCmd (using list)

## Technique Context

T1003.004 represents a specific approach to credential dumping that targets Microsoft Internet Information Services (IIS) configurations. This sub-technique focuses on extracting service account credentials stored in IIS application pool configurations using Microsoft's built-in `appcmd.exe` utility. IIS application pools often run under service accounts that may have elevated privileges, making their credentials valuable to attackers who have gained initial access to web servers.

Attackers use `appcmd.exe` because it's a legitimate administrative tool that can enumerate and display detailed configuration information about IIS application pools, including service account usernames and potentially passwords when configured improperly. The detection community typically focuses on monitoring for `appcmd.exe` executions with specific parameters that dump configuration details, particularly when executed by non-administrative users or in contexts where IIS administration wouldn't be expected.

## What This Dataset Contains

This dataset captures an Atomic Red Team test that attempts to retrieve IIS service account credentials using three variations of `appcmd.exe` commands. The key telemetry includes:

**PowerShell Script Block (EID 4104):** The actual test commands are visible in script block `7218af24-80c1-4729-9f73-bd82f882979e`: `& {C:\Windows\System32\inetsrv\appcmd.exe list apppool /@t:* C:\Windows\System32\inetsrv\appcmd.exe list apppool /@text:* C:\Windows\System32\inetsrv\appcmd.exe list apppool /text:*}`

**Security Process Creation (EID 4688):** Shows PowerShell process 0x1380 created with command line `"powershell.exe" & {C:\Windows\System32\inetsrv\appcmd.exe list apppool /@t:*...}` containing the full appcmd execution sequence.

**Sysmon Process Creation (EID 1):** Two processes are captured - `whoami.exe` (PID 1888) for discovery and PowerShell (PID 4992) with the appcmd command block. The Sysmon events show the complete process hierarchy from the parent PowerShell instance.

**Process Access Events (EID 10):** Multiple process access events show PowerShell processes accessing each other with `GrantedAccess: 0x1FFFFF`, indicating the test framework process management.

## What This Dataset Does Not Contain

The dataset is missing the actual `appcmd.exe` process creation events, which suggests that either:
1. IIS is not installed on this test system (most likely scenario)
2. The sysmon-modular configuration doesn't capture `appcmd.exe` as a suspicious process
3. The commands failed to execute due to missing IIS components

There are no Sysmon ProcessCreate events for `C:\Windows\System32\inetsrv\appcmd.exe`, no network connections, no file access events to IIS configuration files, and no error events indicating failed command execution. The PowerShell script blocks show the commands were invoked, but the absence of subsequent telemetry suggests the technique didn't complete successfully, likely because IIS infrastructure wasn't present on this Windows 11 Enterprise evaluation system.

## Assessment

This dataset has limited utility for detection engineering of the actual T1003.004 technique because the core behavior (appcmd.exe execution and IIS configuration enumeration) doesn't appear to have occurred. However, it does provide value for detecting the reconnaissance and setup phases of this attack technique. The PowerShell script block logging captures the attack commands clearly, and the process creation events show how such techniques might be delivered through PowerShell execution.

For comprehensive T1003.004 detection development, this dataset would need to be supplemented with telemetry from a system with IIS installed where `appcmd.exe` actually executes and attempts to read application pool configurations. The current dataset is more useful for understanding how attackers might deliver these commands rather than the technique's actual execution artifacts.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis (EID 4104)**: Detect script blocks containing `appcmd.exe list apppool` commands with text output formatting parameters (`/@t:*`, `/@text:*`, `/text:*`).

2. **Command Line Pattern Matching (EID 4688)**: Monitor for PowerShell processes with command lines containing `appcmd.exe list apppool` followed by text output modifiers, especially when executed by non-IIS administrator accounts.

3. **Process Creation Sequence (EID 1)**: Alert on PowerShell processes spawning with command blocks that include multiple `appcmd.exe` invocations targeting application pool enumeration.

4. **Suspicious Administrative Tool Usage**: Detect `appcmd.exe` execution patterns that focus on credential-exposing parameters rather than legitimate IIS administration tasks.

5. **PowerShell Module Loading (EID 7)**: Monitor for PowerShell processes loading System.Management.Automation modules in conjunction with command lines containing IIS enumeration commands.

6. **Parent-Child Process Relationships**: Identify PowerShell parent processes spawning child PowerShell instances specifically for `appcmd.exe` execution, indicating potential credential harvesting automation.
