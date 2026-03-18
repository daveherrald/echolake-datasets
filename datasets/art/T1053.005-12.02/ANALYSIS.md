# T1053.005-12: Scheduled Task — Scheduled Task Persistence via Eventviewer.msc

## Technique Context

T1053.005 (Scheduled Task) is one of the most reliably detected persistence mechanisms in Windows environments, precisely because it has well-understood telemetry: `schtasks.exe` command lines in process creation logs, Security EID 4698 (task created), and Task Scheduler operational events (EID 106 registration, EID 141 deletion). This test demonstrates a more sophisticated variant that chains scheduled task persistence with a UAC bypass, creating a task that will execute with elevated privileges without triggering a UAC prompt.

The attack exploits a known UAC bypass through Event Viewer (`eventvwr.msc`). When Event Viewer launches, Windows checks the `HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command` registry key to determine how to open `.msc` files. Because Event Viewer runs elevated (auto-elevate), if an attacker can pre-populate that registry key with an arbitrary executable, launching eventvwr.msc causes the arbitrary executable to run with elevated integrity without a UAC dialog. The attack combines this COM hijack with a scheduled task so the payload executes at every logon, providing both persistence and privilege escalation.

Detection for this compound technique requires visibility across three distinct surfaces: registry modification of COM handler keys under `HKCU\Software\Classes`, scheduled task creation (command-line and event log), and task execution. Security teams frequently detect individual components while missing the chain.

## What This Dataset Contains

This is one of the more telemetry-rich datasets in this batch. The undefended execution succeeds in creating the scheduled task and completing the full attack sequence, generating events across four log channels.

**Security EID 4688 — process creation (9 events):** The complete execution chain is preserved. The pivotal `cmd.exe` command line reveals the full three-stage attack:

```
"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command" /ve /t REG_EXPAND_SZ /d "c:\windows\System32\calc.exe" /f & schtasks /Create /TN "EventViewerBypass" /TR "eventvwr.msc" /SC ONLOGON /RL HIGHEST /F & ECHO Let's run the schedule task ... & schtasks /Run /TN "EventViewerBypass"
```

Individual child process creation records capture `reg.exe` (for the COM key write), `schtasks.exe` (for task creation), and `schtasks.exe` again (for task execution). A cleanup `cmd.exe` runs `reg delete "HKEY_CURRENT_USER\Software\Classes\mscfile\shell\open\command" /f & schtasks /Delete /TN "EventViewerBypass" /F`. All run as `NT AUTHORITY\SYSTEM`.

**Security EID 4698 — scheduled task created (1 event):** The task creation event captures the full task XML under `TaskContent`:

```xml
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-03-14T16:14:21</Date><Author>ACME\ACME-WS06$</Author></RegistrationInfo>
  ...
  <TaskName>\EventViewerBypass</TaskName>
```

**Security EID 4699 — scheduled task deleted (1 event):** Records cleanup of `\EventViewerBypass`.

**Sysmon EID 1 — process create (9 events):** Sysmon captures the full process tree including `cmd.exe` (tagged `T1059.003`), `reg.exe` (tagged `T1012,technique_name=Query Registry`), and `schtasks.exe` (tagged `T1053.005,technique_name=Scheduled Task/Job`). The cleanup `schtasks.exe` command line `schtasks /Delete /TN "EventViewerBypass" /F` is also captured.

**Sysmon EID 13 — registry value set (4 events):** The COM hijack registry write is captured directly:
- `TargetObject: HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command\(Default)`
- `Details: c:\windows\System32\calc.exe`

Additional EID 13 events show the Task Scheduler service (`svchost.exe`) writing the task entry into `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`. The task ID `{F3B32163-7884-4352-88A5-E2A8F168D6C6}` appears in these registry writes.

**Sysmon EID 12 — registry key create/delete (2 events):** `HKU\.DEFAULT\Software\Classes\mscfile\shell\open\command` is deleted during cleanup (EID 12 `DeleteKey`). Another EID 12 records `HKLM\...\Schedule\TaskCache\Tree\EventViewerBypass` deletion by `svchost.exe`.

**Sysmon EID 11 — file create (2 events):** Includes task definition file creation at `C:\Windows\System32\Tasks\EventViewerBypass`.

**Sysmon EID 10 — process access (4 events):** PowerShell accessing child processes with `GrantedAccess: 0x1fffff`, standard test framework artifact.

**Sysmon EID 7 — image load (11 events):** .NET CLR and Defender DLLs in PowerShell processes.

**Sysmon EID 17 — named pipe create (1 event):** PowerShell host pipe.

**Task Scheduler channel (5 events):**
- EID 106: `\EventViewerBypass` registered
- EID 140: `\EventViewerBypass` updated
- EID 110: `\EventViewerBypass` launch attempted
- EID 332: Task failed because no user was logged on (expected for `SC ONLOGON` trigger in a SYSTEM-only session)
- EID 141: `\EventViewerBypass` deleted

**Comparison to the defended dataset:** The defended version captured 36 sysmon, 17 security, and 34 powershell events with 4 task scheduler events. This undefended dataset matches closely: 33 sysmon, 11 security, 104 powershell, 5 task scheduler events. The undefended run's security channel has fewer total events (11 vs 17) primarily because Defender's real-time protection in the defended run generated additional process creation activity. The core technique telemetry — registry modification, task creation, task scheduler events — is present in both, meaning this technique's artifacts survive even with Defender enabled.

## What This Dataset Does Not Contain

The actual UAC bypass execution does not appear because the task's `SC ONLOGON` trigger requires an interactive logon, which did not occur during the test window. The `eventvwr.msc` process creation and any resulting elevated `calc.exe` (the hijacked payload) are absent. This is an expected limitation of the test environment rather than a detection gap.

There is no Sysmon EID 1 for `eventvwr.msc` execution, since the trigger condition (user logon) was never met in the test. Network connections, LDAP queries, and credential activity are absent — they would only materialize if the payload executed and included those behaviors.

## Assessment

This dataset is excellent for detection engineering. It captures the full attack sequence in multiple independent telemetry sources: the chained command line in Security EID 4688, the COM hijack in Sysmon EID 13, the task creation in Security EID 4698, and the task scheduler operational events. A detection team can build rules at any or all of these layers and validate them against this data. The presence of both creation and cleanup events enables testing of alert lifecycle handling.

This dataset is particularly valuable for testing detections targeting the COM hijack component (`mscfile\shell\open\command` registry writes), which is the technique's evasion mechanism — it exploits a legitimate Windows extension point rather than using `schtasks.exe` in an unusual way.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 `TargetObject` containing `mscfile\shell\open\command` with a non-mmc value in `Details` — this is the COM hijack write and directly enables the UAC bypass. Any value other than `%SystemRoot%\system32\mmc.exe "%1" %*` warrants investigation.

2. Security EID 4688 `CommandLine` for `schtasks.exe` containing `/TR "eventvwr.msc"` — using Event Viewer as a scheduled task trigger is highly unusual outside of this specific attack pattern.

3. Security EID 4698 `TaskContent` containing `eventvwr.msc` as the task action payload (the `/TR` argument), confirmed by the XML in the task registration event.

4. The combined sequence of `reg.exe` writing to `HKCU\Software\Classes\mscfile\shell\open\command` immediately followed by `schtasks.exe /Create` within the same parent `cmd.exe` process is a multi-event correlation opportunity.

5. Task Scheduler EID 332 (task failed, no logon session) combined with EID 110 (task launch attempt) for a newly-registered task named with common attacker vocabulary (`Bypass`, `Persist`, `Backdoor`) suggests automated persistence testing.

6. Sysmon EID 12 `DeleteKey` on `HKCU\Software\Classes\mscfile\shell\open\command` shortly after a corresponding EID 13 `SetValue` is a cleanup pattern; the presence of both events within a short window indicates transient COM key hijacking.

7. `schtasks.exe /RL HIGHEST` (run at highest privileges) combined with an `SC ONLOGON` trigger from a non-interactive SYSTEM context is an unusual privilege combination for legitimate scheduled task creation.
