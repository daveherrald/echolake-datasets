# T1112-30: Modify Registry — Windows HideSCAPower Group Policy Feature

## Technique Context

The `HideSCAPower` registry value (`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` set to `1`) hides the power options from the Windows security and session management interface — specifically removing the power-related controls (Shut Down, Restart, Sleep, Hibernate) from the Ctrl+Alt+Del screen and the Start menu power button. This prevents standard interactive logout and system state transition through the normal UI, forcing users to resort to command-line methods or Task Manager to manage system power state.

In post-exploitation contexts, hiding power options can be combined with other session management restrictions to prevent a victim from easily logging out a compromised session, rebooting to clear in-memory malware, or transitioning to a recovery environment. Like HideSCAHealth, HideSCAPower is more operationally motivated than the UI-cosmetic modifications like HideClock or NoFileMenu.

T1112-30 is the final test in this consecutive series of Explorer policy modifications (T1112-19, T1112-21, T1112-22, T1112-24, T1112-27, T1112-28, T1112-30). All seven tests target the same registry path with the same `powershell.exe` → `cmd.exe` → `reg.exe` execution chain, making this dataset series collectively valuable for validating that detection logic covers the path pattern rather than individual value names.

## What This Dataset Contains

This dataset captures 57 events across three channels (36 PowerShell, 4 Security, 17 Sysmon) collected over a 4-second window (2026-03-14T23:50:10Z–23:50:14Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688):**

Four EID 4688 events:
1. `whoami.exe` — pre-test identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAPower /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAPower /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check

**Sysmon Process Creates (EID 1):**

Four EID 1 events:
- `whoami.exe` (PID 4532): parent GUID `{9dc7570a-f431-69b5-e711-000000000600}` (parent PowerShell PID 4672), tagged `T1033`
- `cmd.exe` (PID 2992): full HideSCAPower command, SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`, IMPHASH `D73E39DAB3C8B57AA408073D01254964`, tagged `T1059.003`
- `reg.exe` (PID 6376): full reg add command, SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`, IMPHASH `1085BD82B37A225F6D356012D2E69C3D`, parent GUID `{9dc7570a-f435-69b5-ec11-000000000600}` (cmd.exe), tagged `T1012`
- Fourth process create from cleanup

Process chain: PowerShell (PID 4672, GUID `{9dc7570a-f431-69b5-e711-000000000600}`) → cmd.exe (PID 2992, GUID `{9dc7570a-f435-69b5-ec11-000000000600}`) → reg.exe (PID 6376, parent GUID confirms cmd.exe ancestry).

**Sysmon Image Loads (EID 7):**

9 EID 7 events for the .NET CLR DLL sequence on parent PowerShell (PID 4672): `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`.

**Sysmon Process Access (EID 10):**

3 EID 10 events for the parent PowerShell accessing child processes with `GrantedAccess: 0x1FFFFF`.

**Sysmon Named Pipe Create (EID 17):**

One EID 17 event for the standard PowerShell host pipe `\PSHost.*.DefaultAppDomain.powershell`.

**PowerShell Script Block Logging (EID 4104):**

36 EID 4104 events. As in T1112-27 and T1112-28, the ART test framework timing artifacts appear:
- `$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` — present in the sample set, marking the end of the timed test window

The remaining 4104 events are standard PowerShell runtime boilerplate.

## What This Dataset Does Not Contain

- **Sysmon EID 13 for the HideSCAPower registry write:** The path is not in the Sysmon registry monitoring configuration. The process chain is the only workstation-side evidence.
- **Power button removal events:** No event captures the power button disappearing from the Start menu or Ctrl+Alt+Del screen.
- **System-wide vs. per-user scope clarification:** HideSCAPower applies per-user (HKCU); a system-wide equivalent would target HKLM. No event explicitly captures this scoping distinction.
- **Ambient background events:** Unlike T1112-24 (which had Cribl account enumeration) and T1112-27 (which had SPP task updates), this test window was quiet — only the attack-related events and the standard PowerShell runtime overhead appear.

## Assessment

T1112-30 is the cleanest dataset in the T1112 series: minimal ambient background noise, tight event count (57), and a clear process chain. It is the final test in the consecutive Explorer policy modification series and serves as a baseline "pure signal" dataset against which to compare the higher-background tests like T1112-24.

The binary hash consistency across all seven T1112 Explorer policy tests is now fully established: cmd.exe SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB` and reg.exe SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE` appear in every test in this series, confirming these are the authentic system binaries. Any deviation from these hashes in a production environment using the same Windows build would indicate binary modification or replacement.

Compared to the defended variant (74 events: 35 PowerShell, 12 Security, 27 Sysmon), this undefended version (57 events) is notably smaller — fewer ambient events fell in this collection window. The composition difference (4 Security events here vs. 12 in the defended variant) continues the pattern: Defender's own process creates inflate the Security EID 4688 count in defended runs.

Viewing T1112-30 alongside T1112-19 (first in the series) shows how structurally identical these datasets are despite targeting different value names. This consistency validates that detection at the path level (`HKCU\...\Policies\Explorer`) is the appropriate abstraction, rather than per-value detection.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — HideSCAPower in reg add Command:**
The `reg add` command with `HideSCAPower` targeting the Explorer Policies key is the direct indicator. As with all tests in this series, the path-level pattern provides family coverage.

**Cross-Series Pattern — Seven Consecutive Explorer Policy Modifications:**
When viewed across T1112-19 through T1112-30, seven consecutive `reg add` operations targeting `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` within approximately 90 seconds (23:48:54Z–23:50:14Z) constitute a clear behavioral pattern. A temporal clustering detection — multiple `reg.exe` invocations with the same target path within a short time window — provides higher-confidence attribution than any single instance.

**Sysmon EID 1 — Binary Hash Baseline for cmd.exe and reg.exe:**
The confirmed hash values for cmd.exe (SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`) and reg.exe (SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`) on Windows 11 Enterprise 22H2 (build 22631) provide a stable baseline. In conjunction with IMPHASH values (cmd.exe `D73E39DAB3C8B57AA408073D01254964`, reg.exe `1085BD82B37A225F6D356012D2E69C3D`), these can be used to validate binary integrity in other systems using the same OS version.

**ART Test framework Timing Artifacts as Framework Indicator:**
The `$endEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` script block in EID 4104 is a specific ART test framework artifact. Its presence in script block logging, combined with the PowerShell process creation patterns documented across these datasets, is a reliable indicator that ART is executing in the environment.
