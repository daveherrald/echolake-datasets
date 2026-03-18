# T1018-5: Remote System Discovery — Remote System Discovery - arp

## Technique Context

T1018 Remote System Discovery encompasses techniques adversaries use to gain knowledge about other systems and services in the network environment. The ARP (Address Resolution Protocol) variant specifically leverages the built-in `arp.exe` utility to enumerate devices on the local network segment by displaying the ARP cache, which contains mappings between IP addresses and MAC addresses of recently communicated hosts. This technique is particularly valuable during network reconnaissance phases as it reveals active hosts without generating suspicious network traffic — the information already exists in the local system's cache.

Detection engineers typically focus on process creation events for `arp.exe` with the `-a` parameter, command-line arguments, parent processes, and timing patterns that suggest reconnaissance activities rather than legitimate network troubleshooting.

## What This Dataset Contains

This dataset captures a straightforward execution of `arp -a` via PowerShell. The key execution chain shows:

1. **PowerShell parent process** (PID 6944): `powershell.exe` running as NT AUTHORITY\SYSTEM
2. **Command shell intermediary** (PID 7252): Security event 4688 shows `"cmd.exe" /c arp -a` spawned by PowerShell 
3. **ARP execution** (PID 7776): Security event 4688 captures `arp  -a` (note the double space) spawned by cmd.exe

The Sysmon data provides additional context with EID 1 ProcessCreate events for both cmd.exe and the technique validation via whoami.exe. Notably, Sysmon EID 10 ProcessAccess events show PowerShell accessing both child processes with full access rights (0x1FFFFF), which is normal parent-child behavior but provides useful process relationship confirmation.

Security event 4703 shows token privilege adjustments for the PowerShell process, including elevated privileges like SeBackupPrivilege and SeRestorePrivilege, indicating SYSTEM-level execution.

## What This Dataset Does Not Contain

The dataset lacks the actual ARP output — we see the process execution but not the network reconnaissance results. There are no Sysmon ProcessCreate events for arp.exe itself, which indicates the sysmon-modular configuration's include-mode filtering doesn't classify arp.exe as a suspicious LOLBin despite its reconnaissance potential. 

The PowerShell script block logging (EID 4104) contains only test framework boilerplate (`Set-StrictMode` scriptblocks) rather than the actual command execution, and there's no EID 4103 module logging for the specific arp command execution. No network events or DNS queries are present, as this technique operates on local ARP cache rather than generating network traffic.

## Assessment

This dataset provides solid coverage for detecting ARP-based network reconnaissance through Security event logs. The Security 4688 events with command-line logging capture the complete execution chain and command arguments, which are the primary detection points for this technique. However, the dataset reveals a gap in Sysmon coverage for arp.exe itself — detection engineers should be aware that relying solely on Sysmon ProcessCreate events would miss this execution entirely.

The process relationship data from Sysmon EID 10 adds valuable context for correlating parent-child processes, but the core detection relies on Security audit logs. For organizations without command-line auditing enabled, this technique would generate minimal useful telemetry.

## Detection Opportunities Present in This Data

1. **Process creation detection**: Security EID 4688 events for `arp.exe` with `-a` parameter, particularly when spawned by scripting engines like PowerShell or cmd.exe

2. **Command-line pattern matching**: Process Command Line field containing `arp -a`, `arp.exe -a`, or variations with additional parameters for broader network scanning

3. **Parent process correlation**: PowerShell or cmd.exe spawning arp.exe, especially in rapid succession or combined with other reconnaissance tools

4. **Privilege context analysis**: Network reconnaissance tools running under SYSTEM privileges (as shown in the 4703 token adjustment event) may indicate compromise rather than legitimate administration

5. **Process access patterns**: Sysmon EID 10 events showing PowerShell accessing newly spawned network utilities with full access rights, particularly useful for detecting scripted reconnaissance workflows

6. **Execution timing correlation**: Sequential execution of system discovery tools like whoami.exe followed by network discovery tools like arp.exe within short time windows
