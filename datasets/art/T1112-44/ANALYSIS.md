# T1112-44: Modify Registry — DisallowRun Execution Of Certain Applications

## Technique Context

T1112 (Modify Registry) is a defense evasion and persistence technique where adversaries manipulate the Windows Registry to alter system behavior, hide artifacts, or maintain access. The specific variant tested here involves modifying the DisallowRun policy under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, which prevents specified applications from executing for the current user. This Group Policy setting is commonly abused by malware to disable security tools, system utilities, or forensic applications that defenders might use during incident response. Adversaries often target utilities like `regedit.exe`, `cmd.exe`, `taskmgr.exe`, or antivirus executables to hamper investigation and remediation efforts.

The detection community focuses heavily on registry modifications targeting security-relevant paths, especially those under Policies keys that control application execution, Windows Defender settings, or system security features. The DisallowRun mechanism is particularly notable because it provides a user-mode method to prevent application execution without requiring administrative privileges for the target user's session.

## What This Dataset Contains

This dataset captures a successful execution of the DisallowRun registry manipulation technique. The key events include:

**Process Chain:** PowerShell → cmd.exe → three sequential reg.exe processes, captured in Security 4688 events and Sysmon EID 1 ProcessCreate events. The command line shows: `"cmd.exe" /c reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisallowRun /t REG_DWORD /d 1 /f & reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /f /t REG_SZ /v art1 /d "regedit.exe" & reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /f /t REG_SZ /v art2 /d "cmd.exe"`

**Registry Modifications:** Three sequential reg.exe executions:
1. `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisallowRun /t REG_DWORD /d 1 /f` (enables the DisallowRun policy)
2. `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /f /t REG_SZ /v art1 /d "regedit.exe"` (blocks Registry Editor)
3. `reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /f /t REG_SZ /v art2 /d "cmd.exe"` (blocks Command Prompt)

All reg.exe processes completed with exit status 0x0, indicating successful registry modifications. The technique executed under NT AUTHORITY\SYSTEM context, showing how privileged processes can manipulate user-specific registry hives.

## What This Dataset Does Not Contain

This dataset lacks the actual registry write operations that would typically appear in Sysmon EID 13 (RegistryEvent - Value Set) events. The sysmon-modular configuration likely filters these registry events or they weren't captured during this execution window. Without these events, you cannot directly observe the registry keys being written, only infer the operations from the reg.exe command lines.

The dataset also doesn't contain any evidence of the DisallowRun policy being tested or validated—there are no subsequent attempts to execute the blocked applications (regedit.exe or cmd.exe) that would demonstrate the policy's effectiveness.

No Registry object access events (Security 4657/4656) are present, indicating the audit policy for object access isn't configured for registry monitoring.

## Assessment

This dataset provides excellent process execution telemetry for detecting DisallowRun registry manipulation through command-line analysis. The Security 4688 events with full command-line logging capture the entire attack sequence clearly, making this a strong dataset for developing process-based detections. The Sysmon EID 1 events provide additional process creation details with file hashes and parent-child relationships.

However, the absence of registry modification events (Sysmon EID 13) significantly limits the dataset's utility for registry-focused detection rules. For comprehensive T1112 detection, you would typically want both the process execution telemetry (which this dataset provides) and the actual registry modification events (which are missing).

The clean execution with exit code 0x0 for all processes demonstrates successful technique completion, making this dataset valuable for understanding the technique's process patterns rather than failure scenarios.

## Detection Opportunities Present in This Data

1. **Command-line detection for reg.exe targeting DisallowRun policies** - Monitor for reg.exe executions with command lines containing "DisallowRun" and policy paths under Explorer registry keys

2. **Sequential reg.exe process creation patterns** - Detect multiple reg.exe processes spawned in rapid succession by the same parent process, particularly when targeting security-relevant registry paths

3. **DisallowRun policy enablement detection** - Look for reg.exe adding REG_DWORD value 1 to the DisallowRun policy key as an enabling action

4. **Security tool blocking attempts** - Monitor for reg.exe adding string values under DisallowRun subkeys that reference common security tools, system utilities, or forensic applications

5. **Parent process analysis** - Detect cmd.exe or PowerShell spawning multiple reg.exe processes targeting Group Policy registry locations

6. **Registry path targeting** - Monitor for registry operations targeting `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` and its subkeys

7. **Batch command detection** - Identify cmd.exe executions using `/c` parameter with concatenated registry commands targeting application restriction policies
