# T1124-2: System Time Discovery — PowerShell Get-Date

## Technique Context

T1124 System Time Discovery describes adversaries querying the local system time and time zone to inform their operations. Knowing the local time helps attackers understand the victim's geographic location, time zone, and operational schedule — useful for timing malicious activity to coincide with off-hours periods, for synchronizing distributed actions across compromised systems, or for validating Kerberos ticket timestamps before executing authentication-dependent attacks.

This test uses the PowerShell `Get-Date` cmdlet, which is the simplest possible implementation: a single built-in cmdlet with no external dependencies, no network calls, and no file system writes. The full executed payload is:

```powershell
Get-Date
```

While this is a trivial command, it represents a class of system discovery behaviors where adversaries use built-in OS tools to enumerate environmental context. PowerShell automation frameworks, C2 implants, and post-exploitation frameworks frequently issue `Get-Date` (or the equivalent Win32 API `GetSystemTime`) as part of initial host profiling.

## What This Dataset Contains

The dataset captures 39 Sysmon events, 4 Security events, and 104 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The technique execution is recorded in Security EID 4688. A child PowerShell process spawns with command line:

```
"powershell.exe" & {Get-Date}
```

The parent process is the outer PowerShell ART test framework. Sysmon EID 1 records the same process creation with the spawned `powershell.exe` hashes (SHA256: `3247BCFD...`, IMPHASH: `AFACF6DC...`). Sysmon EID 10 records PowerShell accessing both the pre-technique `whoami.exe` (for context check) and the spawned `powershell.exe` child, both with `GrantedAccess: 0x1FFFFF`.

Sysmon EID 17 records two named pipe creation events for the two PowerShell host processes:
- `\PSHost.134182390110282292.17704.DefaultAppDomain.powershell` (outer test framework)
- `\PSHost.134182390155275195.18220.DefaultAppDomain.powershell` (the Get-Date invocation)

Sysmon EID 11 records two incidental file creation events:
- `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\keyValueLKG.dat` written by `svchost.exe` (background Delivery Optimization service activity)
- `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` written by `powershell.exe` (standard PS initialization)

The Security channel (4 events) contains: one EID 4688 for `whoami.exe` (pre-technique context check), one EID 4688 for the `Get-Date` PowerShell invocation, one EID 4688 for the post-technique `whoami.exe`, and one EID 4688 for the cleanup command block.

The PowerShell channel (104 events, all EID 4104) consists primarily of test framework boilerplate. The substantive blocks captured include:
- `Set-ExecutionPolicy Bypass -Scope Process -Force`
- `$ErrorActionPreference = 'Continue'`
- `try { Invoke-AtomicTest T1124 -TestNumbers 2 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`

`Get-Date` itself does not generate a distinct EID 4104 block because it is executed as a command-line argument to the spawned `powershell.exe` rather than as a script file.

## What This Dataset Does Not Contain

This dataset does not contain any Windows Time Service events, time synchronization telemetry, or W32tm output. `Get-Date` reads from the local system clock via the operating system — it does not trigger W32tm, NTP queries, or any Service Control Manager activity.

No network events are present. There are no Sysmon EID 22 or EID 3 records.

No file writes containing time data are present. `Get-Date` output goes to stdout and is not logged by any channel captured here.

Compared to the defended variant (36 Sysmon / 11 Security / 40 PowerShell), this dataset is larger in the PowerShell channel (104 vs. 40) and nearly identical in Sysmon (39 vs. 36). The Security channel here (4 events) is smaller than the defended variant (11) because Defender was active in the defended variant and generated additional process creation events during scanning. The large PowerShell channel difference (104 vs. 40) again reflects the absence of AMSI in the undefended environment, allowing more script block events to pass through logging.

## Assessment

This is a simple, high-fidelity dataset for the most basic form of PowerShell-based time discovery. The technique itself — `Get-Date` — is extremely low footprint, and the event evidence consists entirely of a process creation record for a PowerShell child process with `{Get-Date}` in the command line.

`Get-Date` on its own is not a meaningful indicator; it is ubiquitous in legitimate PowerShell scripts. What gives this dataset value is the execution context: `NT AUTHORITY\SYSTEM` running `Get-Date` via a double-hop PowerShell invocation with `Set-ExecutionPolicy Bypass` in the surrounding script blocks. This execution context — SYSTEM-context, policy bypass, double-hop PowerShell — is what distinguishes automated post-exploitation discovery from normal administrative scripting.

As a training dataset, this captures the archetypal "noisy" discovery technique: the behavior itself is benign-looking, and detection requires context stacking (who ran it, from what parent, with what surrounding indicators) rather than a single high-confidence indicator.

## Detection Opportunities Present in This Data

**`powershell.exe` spawning `powershell.exe` with a discovery command.** Sysmon EID 1 and Security EID 4688 both record the PowerShell-to-PowerShell chain with `{Get-Date}` as the command argument. Double-hop PowerShell with a single enumeration cmdlet as the payload is characteristic of automated post-exploitation profiling.

**`NT AUTHORITY\SYSTEM` running `Get-Date` via spawned PowerShell.** The `SubjectUserName: ACME-WS06$` in EID 4688 (reflecting the machine account for a SYSTEM-context process) is context that helps distinguish this from a user running `Get-Date` interactively. SYSTEM-context PowerShell running simple discovery commands is worth baseline comparison.

**`Set-ExecutionPolicy Bypass` in script block logging.** EID 4104 captures this characteristic offensive PowerShell setup step. Combined with subsequent discovery cmdlets, it builds a behavioral cluster.

**`whoami.exe` immediately preceding discovery activity.** The ART test framework runs `whoami.exe` before and after each test. In real attacks, adversaries also frequently run `whoami` to confirm their identity context before proceeding with discovery. The `whoami.exe` + time-discovery sequence is a common post-exploitation profiling pattern.
