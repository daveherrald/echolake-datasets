# T1021.002-3: SMB/Windows Admin Shares — Copy and Execute File with PsExec

## Technique Context

T1021.002 (SMB/Windows Admin Shares) is a lateral movement technique where attackers leverage Windows admin shares (like ADMIN$, C$, IPC$) to copy and execute files on remote systems. This is a fundamental technique for lateral movement in Windows networks, commonly used by both ransomware groups and APTs. PsExec is the most well-known tool for this technique, creating a service on the remote host to execute commands.

The detection community focuses heavily on monitoring service creation events (System 7045), SMB traffic patterns, named pipe creation, authentication events, and the characteristic process chains that PsExec creates. PsExec typically copies itself to ADMIN$ share, creates a Windows service, and establishes named pipe communication for command execution.

## What This Dataset Contains

This dataset captures a PsExec execution against localhost, providing clean telemetry of the technique without network complexity. The key evidence includes:

**Process Chain Evidence:**
- Sysmon EID 1: PowerShell spawning `"C:\Windows\system32\whoami.exe"` 
- Sysmon EID 1: PowerShell spawning cmd.exe with the critical command line: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost -accepteula -c C:\Windows\System32\cmd.exe`
- Security EID 4688: Corresponding process creation events with full command lines

**Process Access Indicators:**
- Sysmon EID 10: PowerShell accessing both whoami.exe and cmd.exe with suspicious GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)
- Call stack traces showing System.Management.Automation involvement in process access

**Named Pipe Creation:**
- Sysmon EID 17: PowerShell creating pipe `\PSHost.134178961200537977.4856.DefaultAppDomain.powershell`

**Privilege Escalation Evidence:**
- Security EID 4703: Token right adjustment showing extensive privilege enablement including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and SeBackupPrivilege

## What This Dataset Does Not Contain

This execution appears to have failed based on the cmd.exe exit status of 0x1 in Security EID 4689. Critical missing elements include:

- **No Service Creation Events**: No System EID 7045 events showing PsExec service installation
- **No Remote Process Creation**: No evidence of PsExec successfully spawning processes on the target
- **No File Copy Evidence**: Missing Sysmon EID 11 events showing PsExec binary being copied to ADMIN$ share
- **No Network Authentication**: Since this targets localhost, there are no network logon events (4624/4625)
- **Limited SMB Telemetry**: No network connection events showing SMB session establishment

The failure likely occurred during PsExec's service installation phase, preventing the full technique execution from being captured.

## Assessment

This dataset provides moderate value for detection engineering despite the failed execution. The process creation telemetry clearly shows PsExec invocation with its characteristic command-line patterns, which is often the most reliable detection point. The process access events demonstrate suspicious PowerShell behavior that could indicate process manipulation attempts.

However, the failed execution limits the dataset's utility for understanding complete PsExec lateral movement patterns. The lack of service creation events means this data won't help build detections for the core PsExec mechanism. The localhost target also eliminates valuable network-based detection opportunities.

The privilege escalation indicators and process access patterns remain valuable for building behavioral detections around tools attempting system-level operations.

## Detection Opportunities Present in This Data

1. **PsExec Command Line Detection**: Monitor for processes with command lines containing "psexec", "\\<target>", and "-accepteula" parameters in Security EID 4688 or Sysmon EID 1.

2. **Suspicious Process Access Patterns**: Alert on Sysmon EID 10 events where PowerShell accesses other processes with PROCESS_ALL_ACCESS (0x1FFFFF) permissions.

3. **Bulk Privilege Escalation**: Monitor Security EID 4703 for processes enabling multiple high-privilege tokens simultaneously, particularly SeAssignPrimaryTokenPrivilege and SeBackupPrivilege combinations.

4. **PowerShell Spawning System Tools**: Track Sysmon EID 1 events where powershell.exe spawns cmd.exe or other system utilities with suspicious command lines.

5. **Administrative Tool Process Chains**: Build detections for the pattern of PowerShell -> cmd.exe -> PsExec.exe execution chains that indicate lateral movement tool usage.

6. **Failed Lateral Movement Attempts**: Monitor for cmd.exe processes with non-zero exit codes (Security EID 4689) following lateral movement tool invocations to identify blocked or failed attempts.
