# T1055-2: Process Injection — Remote Process Injection in LSASS via mimikatz

## Technique Context

T1055 Process Injection is a defense evasion and privilege escalation technique where attackers inject code into legitimate processes to evade detection and gain elevated privileges. This specific test (T1055-2) attempts to use mimikatz to perform remote process injection into LSASS (Local Security Authority Subsystem Service), which is a critical Windows security process that handles authentication and stores credentials in memory. LSASS is a prime target for credential dumping attacks, and injecting into it allows attackers to access sensitive authentication data while hiding within a trusted system process. The detection community focuses heavily on monitoring process access events to LSASS, unusual process creations that interact with LSASS, and the characteristic command-line patterns associated with credential dumping tools like mimikatz.

## What This Dataset Contains

The dataset captures a failed attempt to execute mimikatz remotely via PsExec for LSASS injection. The key evidence includes:

**Process Creation Chain**: Security event 4688 shows PowerShell (PID 38740) spawning cmd.exe with the command line `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" /accepteula \\DC1 -c %tmp%\mimikatz\x64\mimikatz.exe "lsadump::lsa /inject /id:500" "exit"`, revealing the full attack methodology.

**Access Denied Blocking**: The cmd.exe process exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution before mimikatz could run.

**Process Access Telemetry**: Sysmon event 10 captures PowerShell accessing whoami.exe with full access rights (`0x1FFFFF`), tagged by the sysmon-modular ruleset as "technique_id=T1055.001,technique_name=Dynamic-link Library Injection".

**Remote Thread Creation**: Sysmon event 8 shows PowerShell creating a remote thread in an unknown process (PID 38988), tagged as "technique_id=T1055,technique_name=Process Injection".

**Privilege Escalation Evidence**: Security event 4703 documents token right adjustments for the PowerShell process, showing elevation of multiple sensitive privileges including `SeSecurityPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege`.

## What This Dataset Does Not Contain

This dataset lacks the core injection telemetry because Windows Defender blocked execution before mimikatz could run. Missing elements include actual LSASS process access events, credential dumping artifacts, network authentication attempts to the target domain controller (DC1), and successful process injection into LSASS. The sysmon-modular configuration's include-mode filtering means we don't see PsExec.exe or mimikatz.exe process creation events in Sysmon EID 1, though Security 4688 provides the command-line evidence. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass) rather than technique-specific script content.

## Assessment

This dataset provides excellent detection value for identifying process injection attempts, even when blocked by endpoint protection. The combination of Security 4688 command-line logging and Sysmon process access/thread creation events offers multiple detection opportunities. The clear command-line indicators (`mimikatz.exe`, `lsadump::lsa /inject`) and process access patterns make this highly useful for building detection rules. However, the lack of successful execution telemetry limits its value for understanding post-injection behaviors or developing detections for successful LSASS credential access.

## Detection Opportunities Present in This Data

1. **Mimikatz Command Line Detection** - Security EID 4688 with command line containing "mimikatz.exe" and LSASS-specific parameters like "lsadump::lsa /inject"

2. **PsExec Lateral Movement with Credential Tools** - Command line patterns showing PsExec execution with credential dumping tools on remote systems

3. **High-Privilege Process Access** - Sysmon EID 10 showing processes accessing other processes with full access rights (0x1FFFFF), especially from PowerShell

4. **Suspicious Remote Thread Creation** - Sysmon EID 8 detecting CreateRemoteThread API calls from PowerShell or other scripting engines

5. **Token Privilege Escalation** - Security EID 4703 showing elevation of sensitive privileges like SeSecurityPrivilege and SeBackupPrivilege in PowerShell processes

6. **Process Injection DLL Loading** - Sysmon EID 7 events tagged with T1055 technique showing .NET runtime and injection-related libraries loaded into PowerShell

7. **Blocked Execution with Credential Tool Indicators** - Process exit codes 0xC0000022 combined with command lines containing known credential dumping tool names
