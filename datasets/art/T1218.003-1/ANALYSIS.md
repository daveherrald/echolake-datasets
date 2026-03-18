# T1218.003-1: CMSTP — CMSTP Executing Remote Scriptlet

## Technique Context

CMSTP (Microsoft Connection Manager Service Profile Installer) is a legitimate Windows utility designed to install Connection Manager service profiles, typically for VPN and dial-up connections. T1218.003 leverages CMSTP's ability to execute code through specially crafted .inf files, making it an attractive living-off-the-land binary (LOLBin) for defense evasion. Attackers use CMSTP because it can bypass application whitelisting, execute remote scriptlets, and run with elevated privileges while appearing as legitimate Windows activity. The detection community focuses on monitoring CMSTP command-line arguments (especially `/s` for silent installation), the presence of suspicious .inf files, and network connections to remote scriptlet URLs.

## What This Dataset Contains

This dataset captures a clean CMSTP execution without the remote scriptlet component. The process chain shows PowerShell (PID 21972) spawning cmd.exe with the command `"cmd.exe" /c cmstp.exe /s "C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003.inf"`, followed by CMSTP execution with `cmstp.exe /s "C:\AtomicRedTeam\atomics\T1218.003\src\T1218.003.inf"`. Security event 4688 captures both process creations with full command lines, while Sysmon event 1 provides additional process creation details including file hashes and parent-child relationships. The `/s` flag indicates silent installation mode, a key indicator for this technique. CMSTP completes successfully (exit status 0x0) as shown in Security event 4689. The dataset also includes standard PowerShell initialization telemetry and a whoami execution for environmental awareness.

## What This Dataset Does Not Contain

Notably absent from this dataset are the network-related events that would typically characterize the "remote scriptlet" aspect of this technique. There are no Sysmon event 3 (NetworkConnect) events showing CMSTP or child processes connecting to remote URLs, no DNS queries (Sysmon event 22), and no evidence of downloaded scriptlet content. The .inf file appears to be locally hosted rather than referencing a remote scriptlet URL. Windows Defender's real-time protection may have prevented the remote connection, or the test environment may have blocked outbound network access. Additionally, there are no file creation events showing temporary scriptlet files or registry modifications that would typically accompany successful remote code execution via CMSTP.

## Assessment

This dataset provides solid telemetry for detecting CMSTP usage patterns but falls short of demonstrating the complete remote scriptlet execution chain. The Security event 4688 command-line logging excellently captures the CMSTP invocation with the crucial `/s` parameter, while Sysmon process creation events provide rich metadata including file hashes and process relationships. However, the absence of network telemetry significantly limits its utility for detecting the most dangerous variant of this technique—remote scriptlet execution. The data is valuable for building detections around CMSTP process behavior and command-line patterns but would need supplementation with network-enabled samples to cover the full technique scope.

## Detection Opportunities Present in This Data

1. **CMSTP Process Creation with Silent Flag**: Monitor Security 4688 and Sysmon 1 for `cmstp.exe` processes launched with `/s` parameter, especially when spawned by non-administrative processes like PowerShell or cmd.exe.

2. **Unusual CMSTP Parent Processes**: Alert on CMSTP spawned by PowerShell, cmd.exe, or other scripting engines rather than typical installers or system processes, as captured in the parent process fields.

3. **CMSTP Command Line with Local INF Files**: Detect CMSTP referencing .inf files in unusual locations (non-system directories) or with suspicious naming patterns like the test file path shown here.

4. **Process Chain Analysis**: Build detection logic for PowerShell → cmd.exe → cmstp.exe process chains, particularly when PowerShell uses execution policy bypass as seen in the PowerShell operational logs.

5. **CMSTP File Hash Baseline**: Use the process creation events' file hash values to baseline legitimate CMSTP usage and alert on unsigned or unusual variants of the binary.

6. **Privilege Escalation Context**: Monitor for CMSTP execution in high-privilege contexts (SYSTEM) when initiated by lower-privilege parent processes, as this may indicate privilege escalation abuse.
