# T1087.002-5: Domain Account — Adfind -Listing password policy

## Technique Context

T1087.002 (Account Discovery: Domain Account) covers adversary reconnaissance of Active Directory to understand the target environment's account and policy landscape. This test focuses specifically on password policy enumeration — querying AD for the domain's lockout duration, lockout threshold, lockout observation window, maximum and minimum password age, minimum password length, password history length, and password properties (`lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties`).

From an attacker's perspective, this information directly informs credential attacks. Knowing the lockout threshold (e.g., five failed attempts) allows a password spray campaign to stay below the detection threshold. Knowing the minimum length and complexity rules helps build a targeted wordlist. Knowing the maximum password age reveals how stale credentials might be. AdFind is a third-party LDAP query tool that has appeared in dozens of documented ransomware and APT intrusions precisely because it provides rich AD query capability from the command line without requiring a PowerShell AD module.

The test invokes AdFind via `cmd.exe` launched from PowerShell, querying the default naming context (`-default`) with base scope (`-s base`) for the listed password policy attributes.

## What This Dataset Contains

The dataset captures approximately twelve seconds of activity (2026-03-14T23:35:03Z–23:35:15Z) on ACME-WS06.acme.local across three channels, totalling 118 events.

**The core AdFind command** appears in both Sysmon EID 1 and Security EID 4688. The Sysmon process creation event (PID 2988) shows:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe"
  -default -s base lockoutduration lockoutthreshold lockoutobservationwindow
  maxpwdage minpwdage minpwdlength pwdhistorylength pwdproperties
```

Parent process is `powershell.exe` (PID 3180) running under `NT AUTHORITY\SYSTEM`. The full argument list makes the intent of the query unambiguous — all eight attributes are password policy fields, and `-default -s base` is the canonical way to query the domain root for policy attributes.

**Security EID 4688** records four process creations. Two `whoami.exe` executions (PIDs 0x1410 and 0x5A4) bracket the test, and two `cmd.exe` spawns (PIDs 0xBAC and 0x1354) represent the AdFind invocation and the cleanup pass. All run under `S-1-5-18` (SYSTEM).

**Sysmon EID 1** captures `whoami.exe` (PID 5136, rule `T1033`) and `cmd.exe` (PID 2988, rule `T1059.003`) with full command lines and SHA256 hashes. The `cmd.exe` hash `SHA256=423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB` represents the standard Windows Command Processor on this build.

**Sysmon EID 10** (4 events) shows the PowerShell parent process (PID 3180) accessing both `whoami.exe` and the child PowerShell instances with access mask 0x1FFFFF (full access), which the test framework requires to wait for and collect results from child processes.

**Sysmon EID 7** (9 events) records DLL loads for the PowerShell process: .NET runtime components and `System.Management.Automation.ni.dll` (rule `T1059.001`).

**Sysmon EID 17** records a named pipe creation consistent with PowerShell pipeline internals.

**PowerShell EID 4104** (95 events) and **EID 4103** (1 event) document the session's script block activity. Meaningful blocks include: `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`, `Invoke-AtomicTest T1087.002 -TestNumbers 5 -Cleanup -Confirm:$false`, and `$ErrorActionPreference = 'Continue'`. The bulk of the 95 EID 4104 events are PowerShell runtime closures fragmented by the script block logger during module load.

## What This Dataset Does Not Contain

AdFind.exe itself does not appear as a process creation event in either the Security or Sysmon channel. The `cmd.exe` launches AdFind as a child process, but because AdFind is not in Sysmon's include-mode ProcessCreate filter, no EID 1 event is generated for it. This is a recurring gap across all AdFind-based ART tests in this dataset series.

No network events capture the LDAP queries. The LDAP bind and search traffic to the domain controller is not represented in host-based telemetry. You would need DC-side Windows Security event log (specifically Event ID 1644 — Expensive, Inefficient, or Long Running LDAP query logging — or Sysmon on the DC) or network capture to observe the actual query.

No output is captured. If AdFind successfully retrieved policy attributes, those values do not appear in any event.

## Assessment

The test executed fully with Defender disabled. The command line is fully preserved in both Security EID 4688 and Sysmon EID 1, providing unambiguous evidence of the AdFind password policy query. Compared to the defended variant (36 Sysmon, 12 Security, 42 PowerShell), this undefended dataset has fewer Security events (4 vs. 12) and fewer Sysmon events (18 vs. 36), but roughly equivalent PowerShell coverage (96 vs. 42). The Security event reduction is interesting — the defended run's higher count likely reflects Defender-spawned processes (MsMpEng, AM Provider Host) generating their own 4688 events in response to the AdFind execution.

The fundamental detection data — the AdFind command line with password policy attributes — is equally present in both variants. The difference is primarily in the volume of surrounding OS activity rather than coverage of the core behavior.

## Detection Opportunities Present in This Data

**Process creation: cmd.exe with AdFind.exe and password policy attributes**: Security EID 4688 and Sysmon EID 1 both capture the full command line. The combination of `AdFind.exe` with attributes like `lockoutthreshold`, `pwdhistorylength`, and `maxpwdage` in a single command line is highly distinctive and has no common legitimate analogue on a standard workstation.

**Parent-child chain: PowerShell → cmd.exe → AdFind**: The process tree (powershell.exe spawning cmd.exe to run AdFind) is a consistent pattern across AdFind-based tests. Detecting this chain, particularly with SYSTEM context, provides a higher-confidence behavioral signal than any single process event.

**PowerShell EID 4104 content**: The script block log captures the full command including `AdFind.exe` and the attribute list. This provides a second independent detection surface for orgs with PowerShell script block logging enabled.

**AdFind execution from non-standard paths**: AdFind runs from `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` — a red team staging path, but the pattern of running AdFind from any path outside expected IT management directories is itself anomalous. In a real environment, AdFind has no legitimate presence on workstations.
