# T1033-7: System Owner/User Discovery — System Owner/User Discovery Using Command Prompt

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries gather information about the users and accounts present on a system. This technique is typically executed early in post-exploitation phases to understand the current security context, identify privileged accounts, and plan lateral movement or privilege escalation activities. Attackers commonly use built-in Windows utilities like `whoami`, `net users`, `query user`, and similar commands to enumerate local accounts, domain users, and active sessions.

The detection community focuses on monitoring process creation events for these reconnaissance commands, especially when executed in sequence or through scripted automation. Key indicators include the execution of multiple user enumeration utilities within short time windows, command-line patterns that combine multiple enumeration commands, and the creation of temporary files to store enumeration results.

## What This Dataset Contains

This dataset captures a comprehensive System Owner/User Discovery sequence executed through PowerShell orchestration. The Security channel shows the complete process chain starting with Security 4688 events:

1. PowerShell spawning `whoami.exe` with command line `"C:\Windows\system32\whoami.exe"`
2. PowerShell spawning `cmd.exe` with a complex command line: `"cmd.exe" /c set file=$env:temp\user_info_%random%.tmp & echo Username: %USERNAME% > %file% & echo User Domain: %USERDOMAIN% >> %file% & net users >> %file% & query user >> %file%`
3. The cmd.exe process spawning `net.exe` with `net users`
4. The net.exe process spawning `net1.exe` (the actual implementation) with `C:\Windows\system32\net1 users`
5. The cmd.exe process spawning `query.exe` with `query user`
6. The query.exe process spawning `quser.exe` with `"C:\Windows\system32\quser.exe"`

Sysmon provides additional granular details through EID 1 (Process Create) events that capture the same process creations with full command lines, parent-child relationships, and process GUIDs. Notably, Sysmon EID 11 (File Create) captures the creation of `C:\Windows\Temp\%file%` by the cmd.exe process, showing where enumeration results would be stored.

The Sysmon EID 10 (Process Access) events show PowerShell accessing both whoami.exe and cmd.exe with full access rights (0x1FFFFF), indicating process monitoring or control behavior typical of scripted execution frameworks.

Exit status codes in Security 4689 events show that net.exe, net1.exe, query.exe, and quser.exe all exited with status 0x1, while whoami.exe and the PowerShell processes exited cleanly with 0x0.

## What This Dataset Does Not Contain

The dataset lacks any output or results from the enumeration commands themselves - we see the process executions but not the actual user/account information that would have been discovered. The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks) and does not capture the actual PowerShell commands that orchestrated this discovery sequence.

Network-related discovery activities are absent, suggesting this test focused purely on local system enumeration rather than domain user discovery that might generate network traffic. There are no registry modifications or additional persistence mechanisms beyond the temporary file creation for storing results.

Windows Defender appears fully active but did not block any of these legitimate system utilities, as expected since these are standard administrative tools being used for their intended purposes.

## Assessment

This dataset provides excellent coverage for detecting T1033 System Owner/User Discovery techniques. The combination of Security 4688 command-line logging and Sysmon EID 1 process creation events captures comprehensive telemetry for this technique. The Security channel provides complete process lineage with full command lines, while Sysmon adds process GUIDs, file hashes, and parent process details that enable robust correlation and threat hunting.

The process access events from Sysmon EID 10 add valuable context about the scripted nature of the execution, showing PowerShell's process monitoring behavior. The file creation events provide additional evidence of result collection activities. The exit codes visible in Security 4689 events could indicate whether enumeration was successful or failed due to permissions.

This dataset would be particularly valuable for testing detection rules that identify multiple user enumeration utilities executed in sequence, PowerShell-orchestrated reconnaissance activities, and the creation of temporary files for storing discovery results.

## Detection Opportunities Present in This Data

1. **Sequential User Enumeration Process Execution** - Multiple user discovery utilities (whoami, net users, query user) spawned within seconds of each other from the same parent PowerShell process

2. **Complex Command-Line Pattern Detection** - The cmd.exe command line contains multiple chained user enumeration commands with output redirection to temporary files

3. **PowerShell-Orchestrated Reconnaissance** - PowerShell spawning multiple system reconnaissance utilities in rapid succession

4. **Net Command User Enumeration** - Detection of `net users` command execution, a classic indicator of local account discovery

5. **Temporary File Creation for Results Storage** - File creation in temp directory (`C:\Windows\Temp\%file%`) by reconnaissance processes for storing enumeration output

6. **Process Access Patterns** - PowerShell accessing spawned reconnaissance processes with full rights, indicating scripted process control

7. **Query Utility Chain Execution** - The query.exe -> quser.exe process chain indicating session enumeration activities

8. **Whoami Command Execution** - Direct execution of whoami.exe from PowerShell for current user context discovery
