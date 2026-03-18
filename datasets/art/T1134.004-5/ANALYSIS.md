# T1134.004-5: Parent PID Spoofing — Parent PID Spoofing - Spawn from New Process

## Technique Context

T1134.004 Parent PID Spoofing is a defense evasion and privilege escalation technique where adversaries manipulate process creation to make a new process appear as if it was spawned by a different parent process than the one that actually created it. This technique is particularly valuable for evading detection systems that rely on process lineage analysis and breaking expected parent-child relationships that defenders monitor.

Attackers commonly use parent PID spoofing to hide malicious processes under legitimate parent processes like explorer.exe, svchost.exe, or other trusted system processes. This can bypass detections that flag unusual process relationships, such as cmd.exe spawning from an unexpected parent or PowerShell launching from non-administrative contexts. The technique leverages Windows APIs like CreateProcess with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute to specify an arbitrary parent process ID.

Detection engineers focus on identifying inconsistencies between the true process creator (available in some telemetry sources) and the spoofed parent, unusual privilege inheritance patterns, and processes with access rights that don't match their apparent lineage.

## What This Dataset Contains

This dataset captures a successful parent PID spoofing attempt using PowerShell and the Atomic Red Team test framework. The attack chain shows:

1. **Initial PowerShell execution** (PID 28880) starting the test scenario with command: `"powershell.exe" & {Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10'}`

2. **Privilege escalation evidence** in Security event 4703, where the PowerShell process (PID 34036) acquires extensive privileges including `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`, and other high-privilege tokens necessary for process manipulation

3. **Process access events** showing the parent spoofing mechanism - Sysmon event 10 captures PowerShell (PID 34036) accessing whoami.exe (PID 38096) with full access rights (0x1FFFFF), followed by accessing another PowerShell process (PID 33596) with the same extensive rights

4. **Spoofed process creation** visible in Sysmon event 1, where a new PowerShell process (PID 33596) is created with the complex command line but shows normal parent-child relationships in the basic telemetry

The PowerShell script block logging captures the actual attack command: `Start-Process -FilePath $Env:windir\System32\notepad.exe -PassThru | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10'`

## What This Dataset Does Not Contain

The dataset lacks the most critical evidence for detecting parent PID spoofing - it doesn't show the actual notepad.exe process creation that should be the target of the spoofing operation. The Sysmon ProcessCreate events only capture PowerShell and whoami.exe processes, missing the notepad.exe process that the script attempts to launch and use as a spoofing target.

Additionally, the dataset doesn't contain any Sysmon process creation events for the final spoofed PowerShell process that should appear to be a child of notepad.exe rather than the true parent. This suggests either the spoofing attempt failed, the process was too short-lived to generate comprehensive telemetry, or the sysmon-modular configuration filtered out the notepad.exe process creation since it's not in the suspicious process patterns.

The Security 4688 events show normal parent-child relationships without revealing the spoofing attempt, and there's no evidence of the technique's success in making the process appear under a different parent in the process tree.

## Assessment

This dataset provides valuable telemetry for detecting parent PID spoofing preparation and access patterns, but falls short of capturing the complete attack chain. The Security event 4703 showing privilege acquisition and Sysmon event 10 showing cross-process access with full rights are strong indicators of process manipulation techniques. However, the absence of the target process creation and the successful spoofed process significantly limits the dataset's utility for developing comprehensive parent PID spoofing detections.

The PowerShell script block logging is excellent for detecting the use of parent spoofing tools and techniques, particularly the `Start-ATHProcessUnderSpecificParent` function calls. The process access telemetry provides good behavioral indicators that could catch similar techniques even when process creation events are missed.

## Detection Opportunities Present in This Data

1. **Privilege escalation detection** - Monitor Security event 4703 for processes acquiring `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` together, which are commonly needed for process manipulation techniques

2. **Cross-process access with full rights** - Alert on Sysmon event 10 where processes access other processes with 0x1FFFFF (full access) rights, especially when the accessing process is PowerShell or other scripting engines

3. **PowerShell process manipulation commands** - Hunt for script block content containing "Start-ATHProcessUnderSpecificParent" or similar parent spoofing function names in PowerShell event 4104

4. **Suspicious PowerShell command patterns** - Detect PowerShell commands that combine `Start-Process -PassThru` with pipe operations to unknown functions, indicating potential process manipulation workflows

5. **Process creation with extensive command-line arguments** - Flag Security event 4688 showing PowerShell processes with complex command lines involving process creation and unknown PowerShell functions

6. **Sequential process access patterns** - Correlate multiple Sysmon event 10 entries from the same source process accessing different targets in quick succession, which may indicate process enumeration before manipulation
