# T1082-7: System Information Discovery — Hostname Discovery (Windows)

## Technique Context

T1082 (System Information Discovery) includes hostname resolution as one of the most fundamental post-access reconnaissance steps. An attacker who has just gained a foothold needs to know what machine they are on — its hostname identifies it within the Active Directory environment, may indicate its role (workstation, server, domain controller), and often appears in service principal names and certificate subjects. Running `hostname` or `cmd.exe /c hostname` is one of the first commands in countless real malware samples and operator playbooks.

This test mirrors T1082-35 (`ver`) in structure: PowerShell spawning `cmd.exe /c hostname` as SYSTEM. Defender does not flag the hostname command, so both defended and undefended variants capture the same technique-relevant telemetry.

## What This Dataset Contains

This dataset covers a 4-second window (2026-03-14T23:33:09Z–23:33:13Z).

**Process execution chain**: Sysmon EID 1 records three processes. `whoami.exe` (PID 4560) at 23:33:10 as a pre-execution check. Then `cmd.exe` (PID 6388) at 23:33:12 with command line `"cmd.exe" /c hostname`, tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. Working directory is `C:\Windows\TEMP\` and the process runs as `NT AUTHORITY\SYSTEM`. A second `whoami.exe` (PID 5812) at 23:33:13 follows.

**Security events**: Three EID 4688 events capture `whoami.exe`, `cmd.exe /c hostname`, and the second `whoami.exe`. The `cmd.exe` event confirms:
- New Process Name: `C:\Windows\System32\cmd.exe`
- Process ID: `0x18f4`
- Creator SID: `S-1-5-18`
- Creator Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**PowerShell script block logging**: 93 EID 4104 events capture the PowerShell runtime initialization. The hostname command itself is a native subprocess launch and does not generate script block entries.

**DLL loading**: Nine Sysmon EID 7 events reflect .NET and PowerShell runtime loading. The low DLL count (versus PowerSharpPack tests) confirms no additional assemblies were loaded beyond the standard PS runtime.

**Process access**: Three Sysmon EID 10 events show the test framework parent PowerShell accessing child processes, flagged as potential injection by sysmon-modular's conservative rules.

**Named pipe**: Sysmon EID 17 records the `\PSHost.*.powershell` communication pipe.

The undefended run (16 sysmon, 3 security, 93 powershell) is comparable to the defended run (36 sysmon, 12 security, 42 powershell). The defended run's higher sysmon/security counts reflect Defender process overhead absent here. The PowerShell event count difference (93 vs 42) likely reflects variations in initialization sequence rather than technique execution differences.

## What This Dataset Does Not Contain

The hostname `ACME-WS06` (the result of the `hostname` command) does not appear in any event log. The command runs non-interactively with output discarded. There are no file writes, no network connections, and no registry reads. The technique's entire event footprint is the `cmd.exe` process creation.

The dataset also lacks any events showing what the attacker does with the hostname information — it is a pure collection event.

## Assessment

The dataset is minimal by design. The technique is two events: a process creation for `cmd.exe /c hostname` and the Security EID 4688 record for the same. The significance is entirely contextual — SYSTEM-privilege PowerShell spawning `cmd.exe /c hostname` from `C:\Windows\TEMP\`, occurring 11 seconds after a `cmd.exe /c ver` command and within a broader sequence of discovery activity spanning minutes.

This dataset is most useful when analyzed alongside the full undefended ART run rather than in isolation.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: `cmd.exe /c hostname` spawned from `powershell.exe` running as `NT AUTHORITY\SYSTEM` is a reliable process-chain indicator. Neither command is inherently malicious; the execution context is what matters.

**Process ancestry and timing**: At 23:33:12, this executes 11 seconds after T1082-35's `ver` command and 12 seconds before T1083-5's directory enumeration. The temporal clustering of multiple discovery commands as SYSTEM is a strong behavioral indicator.

**Working directory**: `C:\Windows\TEMP\` as the PowerShell working directory is anomalous for interactive administration and consistent with scripted test framework execution.

**EID 4688 process chain**: `NT AUTHORITY\SYSTEM` creating `cmd.exe` whose grandparent is also a SYSTEM PowerShell — this specific three-generation chain is reliable for automated discovery activity.
