# T1078.003-13: Local Accounts — Use PsExec to elevate to NT Authority\SYSTEM account

## Technique Context

T1078.003 focuses on adversaries abusing valid local accounts to gain access to systems or escalate privileges. PsExec is a well-known Sysinternals tool that allows remote and local execution of processes with alternative credentials, including the powerful NT AUTHORITY\SYSTEM account. While legitimate for system administration, PsExec is frequently abused by attackers for lateral movement and privilege escalation. The detection community typically focuses on PsExec's named pipe creation, process injection behaviors, and the characteristic command-line patterns when used with the `-s` flag to run as SYSTEM.

## What This Dataset Contains

This dataset captures a successful PsExec execution that elevates to NT AUTHORITY\SYSTEM and executes `whoami` as a proof-of-concept. The key evidence includes:

**Process Creation Chain**: Security event 4688 shows PowerShell (PID 38592) spawning cmd.exe with command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" -accepteula -s %COMSPEC% /c whoami`. This is followed by whoami.exe creation with command line `"C:\Windows\system32\whoami.exe"` running under NT AUTHORITY\SYSTEM context.

**Sysmon Process Creation**: EID 1 events show both cmd.exe (PID 40452) and whoami.exe (PID 40980) executing under NT AUTHORITY\SYSTEM with System integrity level, confirming successful privilege elevation.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (0x1FFFFF), indicating process injection behavior typical of PsExec's operation.

**Privilege Token Adjustment**: Security event 4703 documents extensive privilege enablement including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and SeSecurityPrivilege - critical privileges for process creation and token manipulation.

**Named Pipe Activity**: Sysmon EID 17 shows PowerShell processes creating named pipes (`\PSHost.134179019229548655.38948.DefaultAppDomain.powershell`), though notably missing the characteristic PsExec named pipes.

## What This Dataset Does Not Contain

The dataset is missing several key PsExec indicators that would typically be present. Most significantly, there are no Sysmon ProcessCreate events for the actual PsExec.exe binary execution - this is likely due to the sysmon-modular configuration's include-mode filtering, which may not classify PsExec as a suspicious binary pattern. 

The expected PsExec named pipes (typically `\PSEXESVC` or similar service-related pipes) are not captured, suggesting either the pipes weren't created during this brief execution or Sysmon pipe monitoring didn't capture them. Additionally, there are no file creation events showing PsExec copying itself to remote systems (though this was a local execution).

The PowerShell events contain only standard test framework boilerplate (`Set-ExecutionPolicy Bypass`, `Set-StrictMode`) rather than the actual PsExec invocation commands, indicating the technique execution occurred outside of PowerShell script block logging coverage.

## Assessment

This dataset provides solid evidence of the privilege escalation outcome but lacks some of the characteristic PsExec behavioral indicators that detection engineers typically rely upon. The Security audit logs with command-line logging capture the full execution chain effectively, while Sysmon provides valuable process access and privilege escalation context. However, the missing PsExec.exe process creation event and service-related named pipes limit the dataset's utility for building comprehensive PsExec-specific detections. The data is most valuable for detecting the privilege escalation result rather than the PsExec tool itself.

## Detection Opportunities Present in This Data

1. **Security 4688 Command Line Pattern**: Detect cmd.exe executions with command lines containing "PsExec.exe" and the "-s" flag, particularly when combined with additional command execution patterns.

2. **Process Hierarchy with SYSTEM Context**: Alert on cmd.exe or whoami.exe processes running under NT AUTHORITY\SYSTEM when spawned from user-context PowerShell processes.

3. **Security 4703 Privilege Escalation**: Monitor for token right adjustments enabling multiple high-privilege rights (SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege) within PowerShell processes.

4. **Sysmon Process Access with Full Rights**: Detect EID 10 events where PowerShell accesses newly created processes with 0x1FFFFF (full access) rights, indicating potential process injection.

5. **System Discovery Under SYSTEM**: Flag whoami.exe executions under NT AUTHORITY\SYSTEM context, especially when part of suspicious process chains.

6. **Rapid Process Creation Sequence**: Correlate PowerShell → cmd.exe → system utilities execution patterns within short time windows as potential PsExec or similar tool usage.
