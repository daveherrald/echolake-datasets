# T1105-24: Ingress Tool Transfer — Lolbas replace.exe use to copy UNC file

## Technique Context

T1105 (Ingress Tool Transfer) involves adversaries transferring tools or files from an external system into a compromised environment. This technique is fundamental to multi-stage attacks where initial access provides limited capabilities, requiring additional tools to be brought in for lateral movement, persistence, or data exfiltration.

This specific test demonstrates the abuse of `replace.exe`, a legitimate Windows utility designed for file replacement operations. The replace.exe LOLBIN (Living Off the Land Binary) can copy files from UNC paths, effectively functioning as a file transfer mechanism. Detection engineers focus on unusual process chains involving replace.exe, especially when accessing remote UNC paths or copying files to suspicious locations like temp directories. The technique bypasses traditional file download monitoring since it uses a signed Microsoft binary for network file operations.

## What This Dataset Contains

The dataset captures a complete execution chain showing replace.exe being used to transfer a file from a UNC path. Key telemetry includes:

**Process Creation Chain (Security 4688/Sysmon 1):**
- PowerShell (PID 31652) spawns cmd.exe: `"cmd.exe" /c del %TEMP%\redcanary.cab >nul 2>&1 & C:\Windows\System32\replace.exe \\127.0.0.1\c$\AtomicRedTeam\atomics\T1105\src\redcanary.cab %TEMP% /A`
- cmd.exe (PID 31732) spawns replace.exe: `C:\Windows\System32\replace.exe \\127.0.0.1\c$\AtomicRedTeam\atomics\T1105\src\redcanary.cab C:\Windows\TEMP /A`

**File Operations (Sysmon 11):**
- replace.exe writes `C:\Windows\Temp\redcanary.cab` with creation time `2026-03-13 19:36:44.852` (indicating file transfer from the UNC source)

**Process Access Events (Sysmon 10):**
- PowerShell accesses both whoami.exe and cmd.exe processes with full access (0x1FFFFF), showing PowerShell's process management during execution

**Network Context:**
- The UNC path `\\127.0.0.1\c$\AtomicRedTeam\atomics\T1105\src\redcanary.cab` demonstrates file transfer from a network share (localhost in this case)

## What This Dataset Does Not Contain

The dataset lacks several important detection vectors for this technique:

**Network Activity:** No Sysmon Event ID 3 (NetworkConnect) events show replace.exe establishing SMB connections to the UNC path. This could be due to sysmon-modular filtering or the localhost nature of the transfer not triggering network monitoring.

**Authentication Events:** Missing Security Event ID 4624/4625 logon events or Event ID 4648 explicit credential use that would typically accompany UNC path access.

**Share Access Logs:** No Security Event ID 5140 (network share access) events showing the file being accessed from the UNC path.

**Parent PowerShell Context:** The PowerShell channel contains only test framework boilerplate (Set-StrictMode calls) and execution policy bypasses, missing the actual PowerShell commands that initiated the file transfer operation.

## Assessment

This dataset provides excellent telemetry for detecting LOLBIN abuse of replace.exe for file transfers. The Security 4688 events with command-line logging capture the complete technique execution, including the distinctive UNC path syntax and /A parameter usage. Sysmon Event ID 1 complements this with process creation details and file hash information.

The file creation events (Sysmon 11) provide strong evidence of the transfer's success, showing when the file was created in the target directory. Process access events add behavioral context but may generate false positives in normal PowerShell operations.

The primary limitation is the lack of network-layer visibility into the SMB traffic, which would strengthen detection by correlating process behavior with actual network file access patterns.

## Detection Opportunities Present in This Data

1. **LOLBIN replace.exe with UNC paths** - Monitor Security 4688/Sysmon 1 for replace.exe command lines containing `\\` UNC path syntax, especially with `/A` (add) parameter

2. **Suspicious replace.exe parent processes** - Alert on replace.exe spawned by cmd.exe or PowerShell, particularly when the parent shows signs of automation or scripting

3. **File transfers to temp directories** - Detect replace.exe writing files to `%TEMP%`, `C:\Windows\Temp`, or other temporary locations via Sysmon 11 file creation events

4. **Process chain anomalies** - Flag PowerShell → cmd.exe → replace.exe process chains as indicative of scripted file transfer operations

5. **Replace.exe with network indicators** - Correlate replace.exe execution with file creation times that don't match local system time, suggesting remote file copy

6. **Command line obfuscation patterns** - Monitor for replace.exe commands embedded in longer cmd.exe command lines with redirection operators and command chaining (&)
