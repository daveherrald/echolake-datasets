# T1069.001-1: Local Groups — Permission Groups Discovery - Local

## Technique Context

T1069.001 (Permission Groups Discovery: Local Groups) is a discovery technique where adversaries enumerate local groups on a system to understand privilege structures and identify high-value accounts. Attackers use this information to plan lateral movement, privilege escalation, and persistence strategies. Common tools include `net localgroup`, `Get-LocalGroup`, `whoami /groups`, and direct Windows API calls.

The detection community focuses on monitoring process execution of enumeration tools, PowerShell cmdlets for group discovery, and API calls to local security authority functions. This technique is often part of broader reconnaissance phases and can indicate an adversary mapping out the local security landscape.

## What This Dataset Contains

This dataset captures a straightforward execution of `whoami.exe` without any group enumeration arguments. The Security channel shows process creation and termination for the discovery activity:

- **Security 4688**: Process creation of `"C:\Windows\system32\whoami.exe"` with Creator Process `powershell.exe` (PID 0x494)
- **Security 4689**: Process exit for `whoami.exe` (PID 0x188c) with exit status 0x0

The Sysmon data provides additional process telemetry:
- **Sysmon EID 1**: Process creation for `whoami.exe` (PID 6284) with rule name `technique_id=T1033,technique_name=System Owner/User Discovery`, showing parent process as PowerShell
- **Sysmon EID 10**: Process access event showing PowerShell accessing the `whoami.exe` process with granted access `0x1FFFFF`

The PowerShell operational log contains only execution policy bypass boilerplate (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) and error handling script blocks, with no evidence of the actual enumeration commands.

## What This Dataset Does Not Contain

This dataset lacks the actual local group enumeration activity that T1069.001 typically involves. The `whoami.exe` execution appears to be basic user identification without the `/groups` parameter that would enumerate group memberships. Missing elements include:

- No `net localgroup` commands or similar group enumeration tools
- No PowerShell `Get-LocalGroup`, `Get-LocalGroupMember`, or equivalent cmdlets in the script block logs  
- No Windows API calls to functions like `NetLocalGroupEnum` or `LsaEnumerateAccountsWithUserRight`
- No output capture or redirection of enumeration results
- No evidence of querying specific high-value groups like Administrators, Backup Operators, or Domain Admins

The technique appears to have executed only the basic user discovery component rather than comprehensive local group enumeration.

## Assessment

This dataset has limited utility for T1069.001 detection engineering because it doesn't contain the core group enumeration behaviors that define this technique. While it demonstrates process creation telemetry quality for reconnaissance tools, the actual local group discovery activity is absent. The Sysmon configuration correctly tagged the `whoami.exe` execution under T1033 (System Owner/User Discovery) rather than T1069.001, which is more accurate given the command executed.

For building robust T1069.001 detections, datasets would need to include actual group enumeration commands with their command-line arguments, PowerShell group discovery cmdlets with script block logging, or API-level group enumeration calls captured through ETW or other advanced telemetry.

## Detection Opportunities Present in This Data

1. **Process creation monitoring for discovery tools** - Security 4688 and Sysmon EID 1 events capturing `whoami.exe` execution from PowerShell parent processes

2. **Discovery tool clustering analysis** - Correlate `whoami.exe` execution with other reconnaissance tools in temporal proximity to identify broader discovery campaigns

3. **PowerShell-spawned reconnaissance detection** - Monitor for discovery utilities launched from PowerShell processes, particularly when execution policy is bypassed

4. **Process access pattern analysis** - Sysmon EID 10 shows PowerShell accessing the discovery tool process, which could indicate programmatic execution rather than interactive use

5. **Parent-child process relationship detection** - Identify PowerShell processes spawning multiple discovery tools in sequence as potential automated reconnaissance
