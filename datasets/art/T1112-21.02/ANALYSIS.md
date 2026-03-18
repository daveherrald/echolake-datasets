# T1112-21: Modify Registry — Activate Windows NoControlPanel Group Policy Feature

## Technique Context

Registry modification (T1112) targeting Group Policy keys in `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` is a consistent pattern across this series of tests. Test 21 sets the `NoControlPanel` value to `1`, which disables the Windows Control Panel for the current user. This prevents access to system configuration tools including User Accounts, Windows Defender (via the legacy interface), Network settings, and Windows Update.

From an adversarial perspective, disabling Control Panel is a meaningful friction measure during post-exploitation. A user attempting to re-enable Windows Defender through the Control Panel, change network settings to cut off an attacker's access, or inspect user account settings would find the Control Panel inaccessible. The modification persists across logon sessions and requires either registry access or Group Policy tooling to reverse.

The execution pattern is identical to T1112-19 (NoRun): PowerShell invokes `cmd.exe /c reg add` targeting the same `HKCU\...\Policies\Explorer` path, with only the value name changing from `NoRun` to `NoControlPanel`. This structural similarity across the T1112 series tests is deliberate — it validates that detection logic covers the path pattern rather than just specific value names.

An additional element in this dataset not present in T1112-19 is Task Scheduler activity captured in a separate channel, reflecting background OS scheduling during the collection window.

## What This Dataset Contains

This dataset captures 75 events across four channels (49 PowerShell, 5 Security, 17 Sysmon, 4 Task Scheduler) collected over a 5-second window (2026-03-14T23:49:05Z–23:49:10Z) on ACME-WS06 with Defender disabled.

**Process Creation Chain (Security EID 4688):**

Five EID 4688 events document the execution:
1. `whoami.exe` — pre-test identity check
2. `cmd.exe` with command: `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f`
3. `reg.exe` with command: `reg  add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f`
4. `whoami.exe` — post-test identity check
5. `taskhostw.exe` — unrelated background scheduled task execution

**Sysmon Process Creates (EID 1):**

Four EID 1 events:
- `whoami.exe` (PID 672): parent GUID `{9dc7570a-f3f0-69b5-9511-000000000600}`, tagged `T1033`
- `cmd.exe` (PID 6264): full NoControlPanel command, SHA256 `423E0E810A69AACEBA0E5670E58AFF898CF0EBFFAB99CCB46EBB3464C3D2FACB`, IMPHASH `D73E39DAB3C8B57AA408073D01254964`, tagged `T1059.003`
- `reg.exe` (PID 3192): full reg add command, SHA256 `411AE446FE37B30C0727888C7FA5E88994A46DAFD41AA5B3B06C9E884549AFDE`, IMPHASH `1085BD82B37A225F6D356012D2E69C3D`, parent GUID linking to cmd.exe, tagged `T1012`
- A fourth process create from the post-test phase

The cmd.exe and reg.exe hash values are identical to T1112-19, confirming these are the same binaries on the same system. This hash consistency is expected and valuable for cross-dataset correlation.

**Task Scheduler Channel (EIDs 100, 107, 129, 200):**

Four Task Scheduler events document the Windows Flighting OneSettings RefreshCache task executing:
- EID 107: Task `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` launched due to time trigger
- EID 129: Task launched `taskhostw.exe` with PID 4884
- EID 100: Task started for user `NT AUTHORITY\SYSTEM`
- EID 200: Action "OneSettings Refresh Cache Task Handler" launched

This is genuine OS background activity — Windows Flight settings cache refresh running on a scheduled interval. It is not related to the T1112 test. The appearance of `taskhostw.exe` in the Security EID 4688 process list confirms this scheduled task fired during the collection window.

**PowerShell Script Block Logging (EID 4104):**

49 EID 4104 events, all PowerShell runtime boilerplate.

**Sysmon Image Loads, Process Access, Named Pipe (EIDs 7, 10, 17):**

9 EID 7 events for .NET CLR DLL loads on the parent PowerShell (PID 1544). 3 EID 10 process access events. 1 EID 17 named pipe create.

## What This Dataset Does Not Contain

- **Sysmon EID 13 (Registry Value Set):** As with T1112-19, direct registry write events are not captured by the Sysmon configuration for this path. The process chain evidence is the primary indicator.
- **Control Panel access denial events:** Windows does not log when the Control Panel restriction takes effect or when a user is blocked by it.
- **Rollback of the NoControlPanel modification:** The ART cleanup removes the value after the test, but this occurs outside the collection window.
- **Task Scheduler task content:** The OneSettings RefreshCache task content is not captured in detail, only the execution lifecycle events (start, launch, action).

## Assessment

T1112-21 and T1112-19 are structurally near-identical datasets — same execution pattern, same binary chain, same registry path, different value name. The main difference here is the smaller event count (75 vs. 114 for T1112-19) and the presence of Task Scheduler background activity. The reduced PowerShell count (49 vs. 93 EID 4104 events) reflects timing variation in how many PowerShell runtime fragments are compiled within the collection window.

The Task Scheduler events are genuine background OS activity that will appear in any real environment. Their presence in this dataset is a useful reminder that security datasets collected from live systems contain ambient system noise alongside attack telemetry. The scheduled task (OneSettings RefreshCache) is identifiable by its task name and path, and its presence in the Security log (via `taskhostw.exe` in EID 4688) and Task Scheduler log simultaneously is the expected pattern for legitimate scheduled task execution.

Compared to the defended variant (73 events: 34 PowerShell, 12 Security, 27 Sysmon), this undefended version (75 events) is slightly larger and includes the Task Scheduler channel. The Security channel is again smaller here (5 vs. 12) due to Defender process activity in the defended variant.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — NoControlPanel in reg add Command:**
The command `reg add ... /v NoControlPanel /t REG_DWORD /d 1` targeting the Explorer Policies key is a specific indicator. Combined with the path pattern (any `reg add` to `...\Policies\Explorer`), this covers the full family of Explorer policy key modifications.

**Sysmon EID 1 — cmd.exe with reg.exe Parent Chain:**
The `powershell.exe` → `cmd.exe /c reg add` → `reg.exe` process chain with the Explorer Policies path in the command argument is a reliable behavioral pattern. The IMPHASH values for cmd.exe (`D73E39DAB3C8B57AA408073D01254964`) and reg.exe (`1085BD82B37A225F6D356012D2E69C3D`) are consistent across T1112-19 through T1112-30 on this system.

**Task Scheduler EID 107/100 — Baseline for Legitimate Scheduled Tasks:**
The `\Microsoft\Windows\Flighting\OneSettings\RefreshCache` task appearing in this dataset provides a baseline example of legitimate OS scheduled task execution. When evaluating Task Scheduler events, this task and similar Windows maintenance tasks can be filtered as expected background activity.

**Cross-Test Correlation — Explorer Policy Path as a Family Indicator:**
Six tests in this dataset collection (T1112-19 through T1112-30) all target `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`. A single detection covering any `reg add` to this path covers the entire family, regardless of which specific value name is targeted.
