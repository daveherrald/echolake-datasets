# T1059.001-21: PowerShell — SOAPHound Dump BloodHound Data

## Technique Context

T1059.001 (PowerShell) provides the execution vehicle. The payload is SOAPHound, a .NET tool that enumerates Active Directory by querying domain controllers over Active Directory Web Services (ADWS) using SOAP/HTTP rather than the LDAP protocol used by SharpHound. This distinction matters operationally: ADWS runs on TCP port 9389 rather than LDAP's 389/636, and the traffic uses SOAP-over-HTTP/HTTPS, which may evade network monitoring rules tuned for LDAP enumeration patterns.

SOAPHound performs the same data collection as SharpHound — users, groups, computers, ACLs, domain trusts — and produces output consumable by BloodHound for attack path analysis. The tool requires valid domain credentials and a reachable domain controller. This test invokes the `--bhdump` mode, which performs a full BloodHound data dump rather than building only a cache file.

The full command invoked is:
```
C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $env:USERNAME --password P@ssword1
--domain $env:USERDOMAIN --dc 10.0.1.14 --bhdump --cachefilename c:\temp\cache.txt
--outputdirectory c:\temp\test2
```

Detection opportunities center on: process creation showing SOAPHound.exe with domain credentials in command-line arguments, network connections to port 9389 on a domain controller, and output files written to `c:\temp\` matching the BloodHound JSON format.

In defended environments, SOAPHound.exe is blocked before process creation completes — no EID 1 appears for it, no network connections are recorded, and the PowerShell wrapper exits cleanly (0x0) as if the tool ran but produced no output. This dataset captures the undefended execution.

## What This Dataset Contains

Security EID 4688 records the PowerShell child process (PID 0x1510 in the data, matching the SOAPHound invocation) with the complete command line including cleartext credentials (`--password P@ssword1`) and the target domain controller IP (`--dc 10.0.1.14`). The output directory (`--outputdirectory c:\temp\test2`) and cache file path (`--cachefilename c:\temp\cache.txt`) are both explicit in the command line. Two `whoami.exe` processes (from PowerShell) are also captured in EID 4688.

The PowerShell channel contains 104 EID 4104 events. The script blocks span the test framework overhead and the SOAPHound invocation itself. The sampled blocks include `$ErrorActionPreference = 'Continue'`, `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`, and the cleanup runner.

Sysmon contributes 21 events: 12 EID 7 (ImageLoad), 3 EID 10 (ProcessAccess), 3 EID 1 (ProcessCreate), 2 EID 17 (Pipe), and 1 EID 11 (FileCreate). EID 1 captures `whoami.exe` (PID 5488, parent powershell.exe, tagged T1033) and the PowerShell process (PID 5228) with the SOAPHound command line, tagged `technique_id=T1083,technique_name=File and Directory Discovery` — the Sysmon rule matching on the file-system traversal behavior of the command. A second `whoami.exe` (PID 3232) follows the SOAPHound invocation. EID 10 shows full-access handle opens (0x1FFFFF) from PowerShell (PID 4892) to `whoami.exe` and to the SOAPHound-executing PowerShell (PID 5228). EID 11 records PowerShell writing `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`. EID 17 shows the PSHost named pipe for PID 4892: `\PSHost.134180039969455349.4892.DefaultAppDomain.powershell`.

Compared to the defended version (which showed no SOAPHound.exe process creation and no network activity), this dataset provides the full process execution chain and, critically, the cleartext credential and target infrastructure information in the EID 4688 command line.

## What This Dataset Does Not Contain

Despite SOAPHound requiring network access to `10.0.1.14:9389`, no Sysmon EID 3 (NetworkConnect) events are present. Whether SOAPHound actually connected and retrieved data or whether there was no DC at 10.0.1.14 in this lab's configuration cannot be determined from the telemetry alone. No EID 22 DNS events appear. No file creation events in `c:\temp\test2\` confirm that BloodHound JSON output was written — the only EID 11 is the PowerShell startup profile write, not the collection output.

There is no separate Sysmon EID 1 for `SOAPHound.exe` itself — the tool executes as a child of the PowerShell process, and if the sysmon-modular include list does not match it, no process-create event is generated for the binary. The SOAPHound execution is therefore documented only through the parent PowerShell's command line (EID 4688) rather than a direct SOAPHound process event.

## Assessment

The primary detection value here is in the EID 4688 command line: a binary named `SOAPHound.exe` invoked from an ART atomics path with cleartext domain credentials, a domain controller IP address, and explicit output paths. The credential exposure in the command line (`--password P@ssword1`) is a common pattern in real attacker operations using tools that accept credentials as arguments and is directly observable without decryption or memory analysis.

The absence of network events and output file writes means this dataset cannot confirm successful data collection, only that the execution was attempted with the correct parameters.

## Detection Opportunities Present in This Data

1. EID 4688 `CommandLine` containing `SOAPHound.exe` — the tool name as a literal process name argument.
2. EID 4688 `CommandLine` containing `--password` followed by a plaintext value — credential arguments in a process command line.
3. EID 4688 `CommandLine` containing `--dc` with an IP address (`10.0.1.14`) rather than a hostname — direct IP targeting of a domain controller in a reconnaissance tool invocation.
4. EID 4688 `CommandLine` with `--bhdump --outputdirectory c:\temp\` — BloodHound dump mode writing to a world-writable staging path.
5. Sysmon EID 1 tagged `technique_id=T1083` on a PowerShell process with SOAPHound arguments — the Sysmon rule associating file-directory discovery behavior with the command.
6. EID 4688 showing `C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe` as the executable path — tool staged in the ART atomics directory tree, a path pattern that may generalize to other staged offensive tools.
7. Sysmon EID 10 `GrantedAccess: 0x1FFFFF` from the parent PowerShell to the child PowerShell running SOAPHound — full process access between parent and tool-launching process.
