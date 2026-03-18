# T1547.001-16: Registry Run Keys / Startup Folder — Secedit Used to Create a Run Key in the HKLM Hive

## Technique Context

MITRE ATT&CK T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. This test demonstrates an indirect method for writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` using the Windows Security Configuration and Analysis tool `secedit.exe`. Rather than writing to the registry directly via `reg.exe` or PowerShell, the test imports a security template INF file that includes a run key definition. When `secedit /configure` applies the template, Group Policy infrastructure processes the configuration and writes the run key — with `services.exe` performing the final registry write rather than the originating process.

## What This Dataset Contains

This dataset captures telemetry from the Atomic Red Team test that constructs and applies an INF-format security template (`regtemplate.ini`) using `secedit /import` and `secedit /configure`, causing the Group Policy service to write `calc.exe` as a value under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\calc`.

**Sysmon (41 events):**
- EID 1 (Process Create): `whoami.exe` (test framework identity check). `cmd.exe` spawned by PowerShell with the two-stage command: `secedit /import /db mytemplate.db /cfg "C:\AtomicRedTeam\atomics\T1547.001\src\regtemplate.ini" & secedit /configure /db mytemplate.db`. `SecEdit.exe` as a child of `cmd.exe`.
- EID 7 (Image Load): Multiple DLL loads for PowerShell and `svchost.exe` — standard Group Policy processing triggered by the secedit operation.
- EID 10 (Process Access): PowerShell accessing `whoami.exe`.
- EID 11 (File Create): `svchost.exe` writing a Group Policy template file: `C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\acme.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`. PowerShell startup profile file also written.
- EID 13 (Registry Value Set): Two significant registry writes. First: `services.exe` writing `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\calc` with value `calc.exe` — this is the actual persistence entry, and it is written by `services.exe`, not by `secedit.exe` or `cmd.exe`. Second: `svchost.exe` writing a Task Scheduler task cache entry related to Group Policy processing.
- EID 17 (Pipe Create): Named pipe from PowerShell.
- EID 22 (DNS Query): `svchost.exe` performing a DNS lookup — Group Policy processing activity.

**Security (35 events):**
- EID 4688/4689: Process creates and exits for `powershell.exe`, `whoami.exe`, `cmd.exe`, `SecEdit.exe`, and `conhost.exe`. The `cmd.exe` 4688 event records the full secedit command line.
- EID 4624/4627/4634/4672: Two logon/logoff cycles for machine account or SYSTEM-level Group Policy processing sessions triggered by the secedit configuration apply.
- EID 4703: Token right adjustments for both `services.exe` and `lsass.exe` — Group Policy policy application activity.

**PowerShell (34 events):**
- EID 4103: `Set-ExecutionPolicy -Scope Process -Force` (test framework preamble, appears twice). No `Set-ItemProperty` or equivalent — the actual registry write is not performed by PowerShell.
- EID 4104: All 32 script block events are PowerShell runtime boilerplate (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, etc.). The secedit command is executed via `cmd.exe`, so its logic does not appear as a PowerShell scriptblock.

**System (1 event):**
- EID 1500: Group Policy settings for the computer were processed successfully.

**Application (1 event):**
- EID 1704: Security policy in the Group Policy objects has been applied successfully.

**TaskScheduler (1 event):**
- EID 140: Task Scheduler task `\Microsoft\Windows\GroupPolicy\{...}` updated by `S-1-5-20` (Network Service / Group Policy service) — a side effect of the secedit apply operation.

## What This Dataset Does Not Contain

- No `reg.exe` appears in this dataset — the technique deliberately avoids direct registry tooling.
- The actual `regtemplate.ini` file content is not logged anywhere in this dataset. Its existence is inferred from the `secedit /import` command line, but neither Sysmon nor the Security log captures INF template file content.
- No Defender block occurred; Windows Defender did not prevent either the secedit execution or the resulting registry modification.
- There are no network connections associated with the test itself. The DNS query from `svchost.exe` is Group Policy domain lookup activity.

## Assessment

The test completed successfully, with the notable characteristic that the final registry write to `HKLM\...\Run\calc` is performed by `services.exe` rather than the initiating process chain. This makes attribution harder than in direct `reg.exe` or PowerShell-based approaches — the Sysmon EID 13 event points to `services.exe` as the writing process, which could appear legitimate without context. The Sysmon EID 1 event chain (`powershell.exe` → `cmd.exe` → `secedit.exe`) provides that context, but only if both are correlated. The side-channel artifacts (Group Policy template file write, logon events, Task Scheduler update, Application EID 1704) are distinctive and not present in direct run-key tests.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `SecEdit.exe` spawned with `/import` and `/configure` arguments. `secedit.exe` combined with an INF template targeting registry run keys is an unusual pattern.
- **Sysmon EID 13**: `services.exe` writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*`. While `services.exe` writes run keys during some legitimate operations, this specific key path written by `services.exe` in response to secedit activity is worth investigating.
- **Sysmon EID 11**: `svchost.exe` writing a `GptTmpl.inf` file to the Group Policy DataStore in response to an administratively triggered secedit configure call — useful for identifying this specific path.
- **Application EID 1704** + **System EID 1500**: Group Policy policy application events occurring without a scheduled Group Policy refresh cycle can indicate forced policy application via secedit or similar tools.
- **Security EID 4688**: `SecEdit.exe` command line includes `/import` and `/configure` with a user-controlled INF file path.
- **Correlation**: Linking the `cmd.exe` → `secedit.exe` process chain to the subsequent `services.exe` registry write via timestamps provides the full picture.
