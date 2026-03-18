# T1046-3: Network Service Discovery — Port Scan NMap for Windows

## Technique Context

T1046 Network Service Discovery covers adversary techniques to enumerate services and open ports on network-reachable systems. Port scanning is the most direct form of this activity: by sending probe packets to a range of ports and analyzing responses, attackers build a map of accessible services that can be targeted for exploitation or lateral movement. Nmap is the most widely used port scanner across all platforms and has a native Windows executable that operates without requiring a Unix subsystem.

From an attacker's perspective, running nmap on a Windows endpoint avoids the need to bring in external tools on Linux-like systems and takes advantage of the existing Windows networking stack. Nmap against localhost (127.0.0.1) specifically serves to enumerate services the local machine is running — useful for identifying further pivot points or privilege escalation targets. Detection focuses on nmap's process execution signature, the distinctive TCP connection patterns it generates (SYN probes or ACK scans), and file creation events for nmap output files.

## What This Dataset Contains

This dataset captures a PowerShell-invoked nmap scan of localhost with Defender disabled. The invocation pattern is `"powershell.exe" & {nmap 127.0.0.1}`, where nmap is called as a command within a PowerShell child process context.

Security EID 4688 records the process creation of the child `powershell.exe` (spawned from the parent `powershell.exe` ART test framework, running as `ACME-WS06$` under SYSTEM context) with command line `"powershell.exe" & {nmap 127.0.0.1}`.

Sysmon EID 1 provides the same process creation with parent-child context: the child `powershell.exe` with `ParentCommandLine: powershell` and `CommandLine: "powershell.exe" & {nmap 127.0.0.1}`.

The full EID breakdown shows 21 EID 7 ImageLoad events (all for the PowerShell process), 4 EID 1 ProcessCreate events (2x whoami.exe for test framework identity checks, 2x the nmap-invoking powershell.exe), 4 EID 10 ProcessAccess events, 3 EID 17 named pipe creation events, and 1 EID 11 file creation event.

Critically, there are no `nmap.exe` process creation events in either the Security or Sysmon channels. The Sysmon EID 1 events only show `whoami.exe` and `powershell.exe`. This means nmap was not spawned as a separate process — consistent with nmap not being installed on the test system, or the invocation being handled as a PowerShell alias that failed silently. When `nmap` is called within a PowerShell context and it doesn't exist as a command, PowerShell throws a "command not found" error without creating a child process. This is the same pattern observed in the defended dataset.

The undefended dataset (103 PS, 4 Security, 33 Sysmon) closely mirrors the defended version (46 PS, 10 Security, 36 Sysmon) in structure but with substantially more PowerShell EID 4104 script block events in the undefended run.

## What This Dataset Does Not Contain

No nmap.exe process execution telemetry exists — nmap appears not to have been installed on ACME-WS06 at the time of this test. The lack of EID 1 events for nmap.exe and the absence of any network connection events (Sysmon EID 3) or port scan traffic confirm the scan did not execute.

There are no network events of any kind: no EID 3 connection attempts to localhost ports, no ICMP activity, and no TCP SYN packets that would characterize an nmap scan. The technique name is accurate to the ART test definition, but the dataset does not contain actual port scanning telemetry.

The EID 11 file creation event is likely a PowerShell profile or startup file rather than nmap output, given the absence of nmap execution.

## Assessment

This dataset captures the invocation attempt for nmap-based network discovery, but nmap was not installed on the target system. The value here is limited to the process execution chain showing PowerShell invoking `nmap` as a command — useful for detecting the attempt to use nmap even when the tool is absent. The test framework-level indicators (Security 4688, Sysmon EID 1 for the powershell child process) are genuine and representative.

For detection engineering purposes, this dataset is most useful for the PowerShell process creation pattern where the child process command line contains `nmap` as a bare command invocation. If nmap were installed, the dataset would additionally contain nmap.exe process creation and network connection events. The absence of these events reflects the environment state rather than any defense blocking the technique.

Compared to the defended dataset, the undefended run produced essentially identical structural telemetry — confirming that Defender had no additional role to play when nmap simply wasn't present.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 where `CommandLine` contains `nmap` as a word — even an invocation that fails to execute provides the command intent in the process creation log.

2. Sysmon EID 1 showing `powershell.exe` spawning a child `powershell.exe` where the child command line contains network scanning tool names (`nmap`, `masscan`, `zmap`) — this pattern is unusual in legitimate administrative contexts.

3. If nmap.exe is installed: Sysmon EID 1 for `nmap.exe` with any command line should trigger investigation — nmap has no legitimate administrative use on a standard workstation.

4. If nmap.exe is installed: Sysmon EID 3 network connection events from `nmap.exe` showing rapid sequential connections to multiple ports on the same destination IP — the high-rate connection pattern is distinctive of port scanning.

5. File creation events (Sysmon EID 11) in `%TEMP%` or working directories with `.xml` or `.gnmap` extensions from processes that also executed nmap — nmap output files in scan format.

6. PowerShell EID 4104 script block text containing `nmap` alongside IP address patterns — capturing scripted scan orchestration even when invoked through PowerShell's command execution rather than direct process spawn.
