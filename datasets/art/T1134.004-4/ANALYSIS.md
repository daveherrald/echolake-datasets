# T1134.004-4: Parent PID Spoofing — Parent PID Spoofing - Spawn from svchost.exe

## Technique Context

Parent PID Spoofing (T1134.004) is a defense evasion and privilege escalation technique where adversaries manipulate the parent process identifier when creating new processes. This allows attackers to make their malicious processes appear to originate from legitimate system processes, potentially bypassing security controls that rely on process ancestry for detection. The technique is particularly effective against security tools that whitelist processes based on their parent-child relationships or implement allow-listing based on expected process trees.

Attackers commonly use this technique to spawn processes under trusted system processes like svchost.exe, winlogon.exe, or explorer.exe to blend in with normal system activity. The detection community focuses on identifying anomalous parent-child process relationships, unexpected command lines from system processes, and processes created with unusual access rights or privileges.

## What This Dataset Contains

This dataset captures a successful parent PID spoofing execution where PowerShell spawns a child process using a spoofed parent PID from svchost.exe. The key telemetry includes:

**Process Creation Chain in Sysmon EID 1:**
- Initial PowerShell process (PID 37752) with command: `"powershell.exe" & {Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ProcessId -Filter \"Name = 'svchost.exe' AND CommandLine LIKE '%%'\" | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10'}`
- Spawned whoami.exe (PID 32340) with legitimate parent relationship: `ParentProcessId: 37752` and `ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Spawned PowerShell process (PID 22740) showing similar legitimate parent relationships

**PowerShell Script Block Logging (EID 4104):**
The technique execution is captured in script block: `Get-CimInstance -ClassName Win32_Process -Property Name, CommandLine, ProcessId -Filter \"Name = 'svchost.exe' AND CommandLine LIKE '%'\" | Select-Object -First 1 | Start-ATHProcessUnderSpecificParent -FilePath $Env:windir\System32\WindowsPowerShell\v1.0\powershell.exe -CommandLine '-Command Start-Sleep 10'`

**Process Access Events (Sysmon EID 10):**
Two process access events show PowerShell accessing both the whoami.exe and the spoofed PowerShell process with full access rights (GrantedAccess: 0x1FFFFF).

**Security Event Logging:**
Security EID 4688 events capture the same process creations with complete command-line arguments, and EID 4703 shows token privilege adjustments including SeAssignPrimaryTokenPrivilege and other system-level privileges.

## What This Dataset Does Not Contain

Critically, this dataset does not show evidence of successful parent PID spoofing. All Sysmon EID 1 events show correct parent-child relationships - the spawned processes correctly identify their actual parent PowerShell process rather than showing svchost.exe as the parent. This suggests either:

1. The technique execution failed to successfully spoof the parent PID
2. The Start-ATHProcessUnderSpecificParent function may not have properly implemented the spoofing mechanism
3. Windows security mechanisms prevented the parent PID manipulation

The dataset lacks any processes showing svchost.exe as their parent when they should logically have been spawned by the PowerShell script. There are no Sysmon ProcessCreate events showing the telltale signs of successful parent PID spoofing, such as unexpected child processes under system processes.

Additionally, the dataset does not contain any error messages or failure indicators that would help explain why the spoofing attempt may not have succeeded.

## Assessment

This dataset provides limited utility for detection engineering of successful parent PID spoofing, as the technique appears to have failed to achieve its intended goal. However, it does offer value for detecting the attempt itself. The combination of PowerShell script block logging, process creation events, and process access events provides good coverage of the setup and execution phases of the attack.

The dataset is most useful for building detections around the reconnaissance phase (CIM queries for svchost.exe processes) and the privilege escalation attempt (token adjustments captured in EID 4703). For organizations wanting to detect successful parent PID spoofing, this dataset would need to be supplemented with examples where the technique actually succeeds.

## Detection Opportunities Present in This Data

1. **PowerShell CIM reconnaissance queries** - Script block logging captures `Get-CimInstance -ClassName Win32_Process` filtering for svchost.exe processes, which is reconnaissance behavior prior to parent PID spoofing attempts.

2. **Suspicious PowerShell functions** - The `Start-ATHProcessUnderSpecificParent` function name in script blocks is a clear indicator of process manipulation attempts.

3. **Process access with full privileges** - Sysmon EID 10 events showing PowerShell processes accessing other processes with 0x1FFFFF (full access) rights, particularly when combined with process creation attempts.

4. **Token privilege escalation** - Security EID 4703 showing PowerShell processes enabling dangerous privileges like SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and SeSecurityPrivilege.

5. **Parent-child process validation** - While spoofing failed here, monitoring for processes that claim system processes as parents when the command line or context doesn't match expected behavior.

6. **PowerShell execution policy bypass** - The Set-ExecutionPolicy bypass commands in PowerShell logging combined with process manipulation attempts indicate potential malicious activity.
