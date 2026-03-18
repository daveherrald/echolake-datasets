# T1036.004-1: Masquerade Task or Service — Creating W32Time similar named service using schtasks

## Technique Context

T1036.004 (Masquerade Task or Service) is a defense evasion technique where adversaries create scheduled tasks or services with names that closely mimic legitimate Windows components. This test creates a scheduled task named `win32times` — a deliberate near-homoglyph of `W32Time`, the Windows Time service. The task is configured to run as `SYSTEM` on a daily schedule, executing `cmd /c powershell.exe -ep bypass -file c:\T1036.004_NonExistingScript.ps1`.

The naming strategy is the core of this technique: analysts reviewing the task list or searching for scheduled task creation events may overlook `win32times` as a variant of the legitimate `W32Time` service. In real deployments, attackers use this approach to establish persistence that survives casual review. The task name can blend in with dozens of legitimate Windows scheduled tasks, many of which have similarly-formatted names. The `-ep bypass` flag in the payload command line and a non-existent script path are characteristic of persistence mechanisms that point to a payload the attacker controls or will place later.

Detection focuses on task creation events (Security EID 4698, Sysmon EID 12/13), the registry keys written to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`, and the file system artifact at `C:\Windows\System32\Tasks\win32times`. Matching newly-created task names against a known-good baseline or fuzzy-matching against legitimate Windows task names is a practical detection strategy.

## What This Dataset Contains

This dataset contains 1,394 events: 105 PowerShell events, 1,264 Security events, 22 Sysmon events, and 3 Task Scheduler events. The Security channel is dominated by 1,255 EID 4663 (object access) events — a Windows Update / SxS component enumeration burst triggered during the test window, unrelated to the scheduled task creation but captured because the object access audit policy logs all file access during this period.

The attack-relevant events are crisp despite the volume. Security EID 4698 records the scheduled task creation: `SubjectUserName: ACME-WS06$`, `TaskName: \win32times`. Security EID 4699 confirms the cleanup deletion: `TaskName: \win32times`. The schtasks process launches are captured in EID 4688: `schtasks /create /ru system /sc daily /tr "cmd /c powershell.exe -ep bypass -file c:\T1036.004_NonExistingScript.ps1" /tn win32times /f` followed by `schtasks /query /tn win32times` and the cleanup `schtasks /tn win32times /delete /f`.

Sysmon provides the registry-level evidence. EID 13 (registry write) shows `svchost.exe` writing three keys: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\win32times\Id` (GUID `{4F1F88B6-F8D6-486F-96EA-C03DA5673931}`), `\win32times\SD` (security descriptor, binary data), and `\win32times\Index` (DWORD). EID 12 (registry key delete) records the cleanup removal of the task cache key. EID 11 (file create) shows `svchost.exe` creating `C:\Windows\System32\Tasks\win32times` — the task definition XML file. EID 7 shows `schtasks.exe` loading `taskschd.dll` (tagged `technique_id=T1053`). Two Sysmon EID 3 (network connection) events show `MsMpEng.exe` connecting to `48.211.71.202:443` — Defender cloud lookups triggered by the scheduled task activity.

The Task Scheduler channel contains three events: registration of `\win32times` (EID 106), an update (EID 140), and deletion (EID 141).

Compared to the defended dataset (46 Sysmon, 22 Security, 35 PowerShell, plus system/wmi/taskscheduler events), the undefended version has significantly more Security events due to the concurrent object access logging burst, while Sysmon and other channels are comparable.

## What This Dataset Does Not Contain

The actual task definition XML content is not visible in the events — it exists as `C:\Windows\System32\Tasks\win32times` but the file content (which would contain the full task configuration including the malicious command) is captured only as a file creation event, not its contents.

The 1,255 EID 4663 events covering `C:\Windows\WinSxS\FileMaps\` paths are entirely unrelated to the technique and represent a collision between the test timing and Windows Update/SxS component enumeration. This volume would be absent in a quieter system or different test timing.

## Assessment

This is an excellent dataset for scheduled task masquerade detection. The Sysmon registry write events for `TaskCache\Tree\win32times` alongside the Security EID 4698 task creation event and the file creation of `C:\Windows\System32\Tasks\win32times` provide three independent detection channels for the same event. The Task Scheduler operational log adds a fourth. The task name `win32times` vs. legitimate `W32Time` is the exact fuzzy-matching scenario detection engineers should test their rules against. Despite the large Security event volume (driven by unrelated OS activity), the technique-specific signals are clean and actionable.

## Detection Opportunities Present in This Data

1. Security EID 4698 (scheduled task created) for a task name closely resembling a known Windows service name — fuzzy name matching (Levenshtein distance or known-bad name list) against newly-registered task names is the primary detection for this technique.

2. Sysmon EID 13 writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<new_task_name>` where the task name closely resembles a legitimate Windows component is a registry-level anchor.

3. Sysmon EID 11 creating `C:\Windows\System32\Tasks\<task_name>` combined with EID 13 for the matching `TaskCache` registry key provides a correlated multi-event detection.

4. EID 4688 for `schtasks.exe` with a command line containing both `/ru system` and `-ep bypass` (execution policy bypass in the task action) is a strong indicator of malicious scheduled task creation.

5. Task Scheduler EID 106 (task registered) for any task name not present in a known-good baseline of expected tasks, especially when combined with a task action containing `powershell.exe`, `cmd.exe`, or other execution frameworks.

6. Security EID 4699 (scheduled task deleted) shortly after EID 4698 for the same task name indicates cleanup behavior — detecting the creation-deletion pair is useful for identifying short-lived persistence testing.
