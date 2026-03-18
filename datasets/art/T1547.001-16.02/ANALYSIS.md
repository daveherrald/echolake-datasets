# T1547.001-16: Registry Run Keys / Startup Folder — secedit Used to Create a Run Key in the HKLM Hive

## Technique Context

T1547.001 covers persistence and privilege escalation through Windows registry run keys and startup folders. This test demonstrates an indirect method for writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` using the Windows Security Configuration and Analysis tool `secedit.exe`. Rather than invoking `reg.exe` or PowerShell's `Set-ItemProperty` directly, the test supplies a pre-authored INF-format security template (`regtemplate.ini`) containing a run key definition. When `secedit /configure` applies the template, the Windows Group Policy infrastructure processes the configuration and writes the run key — with `services.exe` performing the final registry write rather than the calling process.

This indirection matters for detection. A defender searching for process trees where `reg.exe` or `powershell.exe` write to `HKLM\...\Run` will miss this technique entirely. The registry write is attributed to `services.exe`, and the execution chain goes through `secedit.exe` and the Group Policy service. This is a living-off-the-land technique using a signed Windows binary that has legitimate administrative uses.

This dataset was collected on ACME-WS06 (Windows 11 Enterprise Evaluation, domain `acme.local`) with Windows Defender fully disabled via Group Policy. Compare with the defended variant in `datasets/art/T1547.001-16` for the same test against an active Defender installation.

## What This Dataset Contains

The test executed as `NT AUTHORITY\SYSTEM` via QEMU guest agent. A `cmd.exe` process runs the two-stage command: `secedit /import /db mytemplate.db /cfg "C:\AtomicRedTeam\atomics\T1547.001\src\regtemplate.ini"` followed by `secedit /configure /db mytemplate.db`. The template causes `calc.exe` to be registered as a run key entry.

**Sysmon (33 events — EIDs 1, 7, 10, 11, 13, 17, 22):**

EID 1 (ProcessCreate) captures three significant processes:
- `whoami.exe` (test framework identity check, tagged T1033)
- `cmd.exe` spawned by `powershell.exe`, tagged `T1059.003`, with full command line: `"cmd.exe" /c secedit /import /db mytemplate.db /cfg "C:\AtomicRedTeam\atomics\T1547.001\src\regtemplate.ini" & secedit /configure /db mytemplate.db`
- A second `whoami.exe` at cleanup

Note that `SecEdit.exe` itself does not appear as an EID 1 event in the Sysmon sample set — the Sysmon include-mode `ProcessCreate` filter does not match `secedit.exe` as a suspicious binary, so its spawn is not captured by Sysmon. It is captured in Security EID 4688 (see below).

EID 11 (FileCreate) shows `services.exe` writing `C:\Windows\security\logs\scesrv.log` — the Security Configuration Engine log produced when Group Policy applies the secedit template. This is a characteristic artifact of secedit-based persistence.

EID 22 (DNSQuery) shows `svchost.exe` querying `ACME-DC01.acme.local` twice — Group Policy processing reaching out to the domain controller as part of the secedit configuration apply.

EID 13 (RegistrySetValue) is present but the samples captured do not show the actual `HKLM\...\Run\calc` write — that write is attributed to `services.exe` and may be present in the full `data/sysmon.jsonl`. The Sysmon configuration monitors this registry path, so the EID 13 for the run key write is expected to be in the full dataset.

**Security (13 events — EIDs 4688, 4624, 4672, 4634, 4702):**

EID 4688 records all process creations with full command lines:
- `powershell.exe` (outer test framework)
- `whoami.exe` (identity check)
- `cmd.exe` with the full two-stage secedit command
- `SecEdit.exe` with arguments `/import /db mytemplate.db /cfg "C:\AtomicRedTeam\atomics\T1547.001\src\regtemplate.ini"`
- A second `SecEdit.exe` with arguments `/configure /db mytemplate.db`
- `svchost.exe -k netsvcs -p -s gpsvc` — the Group Policy client service spawned as a side effect of the secedit configuration apply

EID 4624 and 4634 record machine account logon/logoff events triggered by Group Policy processing. EID 4702 records a scheduled task modification associated with Group Policy — an artifact of the secedit configuration apply workflow.

The Application channel (EID 1704) confirms: `Security policy in the Group policy objects has been applied successfully.`

The System channel (EID 1500) notes: `The Group Policy settings for the computer were processed successfully.`

The TaskScheduler channel (EID 140) records a task update triggered by Group Policy policy application.

**PowerShell (96 events — EIDs 4103, 4104):**

EID 4104 script blocks are primarily PowerShell runtime boilerplate. The test action runs via `cmd.exe /c secedit` and does not generate substantive script block logging for the persistence mechanism itself. The largest script block is the ART test framework cleanup stub: `try { Invoke-AtomicTest T1547.001 -TestNumbers 16 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`.

## What This Dataset Does Not Contain

- No Sysmon EID 1 for `secedit.exe` or `svchost.exe` — the include-mode ProcessCreate filter does not match these processes.
- The `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\calc` registry write, attributed to `services.exe`, may not appear in the Sysmon sample set but should be present in the full `data/sysmon.jsonl` given the EID breakdown shows 2 EID 13 events.
- No execution of `calc.exe` occurs — the run key only fires at the next user logon.
- The `regtemplate.ini` source file content is not captured in any log — the template defines what gets registered, but its contents are not logged by any Windows telemetry source without additional file auditing.

## Assessment

This dataset is a strong example of a proxy-write persistence technique, where the actor's process never directly touches the target registry key. The chain is: `powershell.exe` → `cmd.exe` → `secedit.exe` → Group Policy service → `services.exe` → `HKLM\...\Run`. Compared to the defended variant (41 Sysmon, 35 Security, 34 PowerShell events), the undefended run produces similar Sysmon and PowerShell counts (33 and 96 respectively) but fewer Security events (13 vs. 35). The large Security event count in the defended variant suggests Defender triggers additional process auditing or logging when present.

The Group Policy side effects — DNS queries to the DC, `svchost.exe` spawn, EID 4624 logon events, EID 1704 application log entry — are all present and provide corroborating context for the secedit-based persistence registration.

## Detection Opportunities Present in This Data

The following observable events in this dataset support detection:

- **Security EID 4688** recording `cmd.exe` with a command line containing both `secedit` and `/import` combined with a user-controlled `.ini` file path — the full command is captured including the `regtemplate.ini` path under `C:\AtomicRedTeam\atomics\`.

- **Security EID 4688** recording `secedit.exe` as a child of `cmd.exe` or any non-system parent, especially with `/import` and `/configure` arguments operating on a database file in a non-standard location (`mytemplate.db` in the working directory).

- **Sysmon EID 11 (FileCreate)** showing `services.exe` writing to `C:\Windows\security\logs\scesrv.log` in close temporal proximity to a `secedit.exe` execution — this log is written when the Group Policy security template is applied.

- **Sysmon EID 22 (DNS)** showing `svchost.exe` querying the domain controller immediately after a `secedit /configure` execution — Group Policy reaching out to the DC is expected behavior but correlates with the secedit timeline.

- **Multi-channel correlation**: combining the EID 4688 `secedit` command line with the Application EID 1704 (`Security policy applied successfully`) and System EID 1500 creates a high-confidence indicator of a completed secedit-based persistence registration.
