# T1218-16: System Binary Proxy Execution — System Binary Proxy Execution - Wlrmdr Lolbin

## Technique Context

System Binary Proxy Execution (T1218) is a defense evasion technique where attackers leverage legitimate, signed system binaries to proxy execution of malicious payloads. The wlrmdr.exe (Windows Logon Reminder) binary is a lesser-known "Living off the Land" (LOLBin) that can be abused to execute arbitrary applications. This technique exploits the trust inherent in signed Microsoft binaries to bypass application whitelisting solutions and evade detection systems that focus on unsigned or suspicious executables.

The detection community primarily focuses on identifying unusual command-line parameters passed to legitimate system binaries, process ancestry chains that deviate from normal usage patterns, and execution of unexpected applications through proxy binaries. For wlrmdr.exe specifically, normal usage is extremely rare in enterprise environments, making any execution potentially suspicious.

## What This Dataset Contains

This dataset captures a successful wlrmdr.exe proxy execution launching calc.exe. The attack chain begins with PowerShell executing the command `wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u "C:\Windows\System32\calc.exe"`. 

Key events include:
- **Security 4688**: PowerShell process creation with command line `"powershell.exe" & {wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u "C:\Windows\System32\calc.exe"}`
- **Security 4688**: Wlrmdr.exe process creation with full command line `"C:\Windows\system32\wlrmdr.exe" -s 3600 -f 0 -t _ -m _ -a 11 -u C:\Windows\System32\calc.exe`
- **Security 4688**: Calc.exe process creation with parent wlrmdr.exe
- **PowerShell 4104**: Script block logging capturing the exact command `& {wlrmdr.exe -s 3600 -f 0 -t _ -m _ -a 11 -u "C:\Windows\System32\calc.exe"}`

The process chain shows: PowerShell (PID 43696) → PowerShell (PID 13904) → wlrmdr.exe (PID 14308) → calc.exe (PID 8144). Sysmon captured process access events (EID 10) showing PowerShell accessing both wlrmdr.exe and the spawned calc.exe process with full access rights (0x1FFFFF).

## What This Dataset Does Not Contain

The dataset lacks Sysmon ProcessCreate events (EID 1) for wlrmdr.exe and calc.exe because the sysmon-modular configuration uses include-mode filtering that only captures known-suspicious process patterns. Wlrmdr.exe is not in the standard LOLBin detection rules, and calc.exe is considered a benign system utility.

The PowerShell channel contains mostly test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) along with the actual technique execution, but lacks detailed PowerShell operational events beyond basic script block logging.

No network connections, file modifications, or registry changes are captured, as this technique simply proxies process execution without additional persistence or communication mechanisms.

## Assessment

This dataset provides excellent coverage for detecting wlrmdr.exe proxy execution through command-line analysis. The Security channel's process creation events with full command-line logging capture the complete attack chain, while PowerShell script block logging preserves the exact syntax used. The presence of process access events in Sysmon adds additional behavioral context.

The primary limitation is the absence of Sysmon ProcessCreate events for the core technique components, but this is offset by comprehensive Security audit logging. The dataset would be stronger with network monitoring to detect any potential follow-on activity and file system monitoring to capture any dropped payloads.

## Detection Opportunities Present in This Data

1. **Wlrmdr.exe execution detection** - Monitor Security 4688 events for wlrmdr.exe process creation, as this binary has minimal legitimate usage in enterprise environments

2. **Suspicious wlrmdr.exe command-line parameters** - Alert on wlrmdr.exe with `-u` parameter followed by executable paths, particularly when combined with other suspicious parameters like `-a 11`

3. **Unusual process ancestry** - Detect wlrmdr.exe spawned by PowerShell or other scripting engines, as normal usage would typically be user-initiated

4. **PowerShell proxy execution commands** - Monitor PowerShell script block logging (4104) for commands containing "wlrmdr.exe" with execution parameters

5. **Process access patterns** - Correlate Sysmon process access events (EID 10) where PowerShell accesses wlrmdr.exe with full privileges (0x1FFFFF) as potential injection preparation

6. **Calc.exe spawned by non-standard parent** - Flag calc.exe process creation when the parent process is wlrmdr.exe or other unexpected system binaries

7. **LOLBin execution correlation** - Stack rank environments by frequency of legitimate system binary usage to identify outliers and potential proxy execution attempts
