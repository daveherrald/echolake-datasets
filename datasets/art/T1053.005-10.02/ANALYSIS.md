# T1053.005-10: Scheduled Task — Scheduled Task ("Ghost Task") via Registry Key Manipulation

## Technique Context

T1053.005 covers the use of Windows Task Scheduler to persist malicious execution, escalate privileges, or execute code at defined intervals or triggers. The standard detection surface for scheduled tasks is well-established: `schtasks.exe` command-line arguments, Security EID 4698 (task created), and Task Scheduler operational log events appear in the vast majority of detection rule libraries. The "Ghost Task" technique exists specifically to subvert this detection surface.

Ghost tasks are created by writing directly to the `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` registry hive rather than going through the official Windows Task Scheduler COM interface or `schtasks.exe`. Because the Task Scheduler service reads task definitions from this registry location, a task written directly to the registry will be executed by the service but will not generate the standard EID 4698 (task created) event or the Task Scheduler EID 106 (task registered) event — the telemetry sources that most organizations rely upon for scheduled task detection. This makes Ghost Tasks significantly more evasion-capable than conventional scheduled task persistence.

The implementation in this test uses `GhostTask.exe` (an open-source proof-of-concept tool) executed via `PsExec.exe` to run as SYSTEM. The task name chosen is `lilghostie`, with `cmd.exe /c notepad.exe` as the task action.

## What This Dataset Contains

This dataset captures the execution attempt of the GhostTask technique with Defender disabled. The key evidence survives in process creation telemetry rather than task registration events.

**Security EID 4688 — process creation (4 events):** Two pairs of process creation events document both the task creation attempt and the subsequent cleanup. The creation command line is fully preserved:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost -accepteula -s "cmd.exe" & "C:\AtomicRedTeam\atomics\..\ExternalPayloads\GhostTask.exe" \\localhost add lilghostie "cmd.exe" "/c notepad.exe" $env:USERDOMAIN + '\'
```

The cleanup command line is also captured:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\PsExec.exe" \\localhost -accepteula -s "cmd.exe" & "C:\AtomicRedTeam\atomics\..\ExternalPayloads\GhostTask.exe" \\localhost delete lilghostie > nul
```

Both run under `NT AUTHORITY\SYSTEM` (S-1-5-18), with `C:\Windows\System32\cmd.exe` as the `NewProcessName` and parent `powershell.exe`. The presence of both add and delete commands confirms the technique ran and cleanup was attempted.

**Sysmon EID 1 — process create (4 events):** Sysmon captures `whoami.exe` (twice, tagged `technique_id=T1033`) and `cmd.exe` (tagged `technique_id=T1059.003,technique_name=Windows Command Shell`) spawned by PowerShell. The GhostTask.exe and PsExec.exe binaries themselves do not appear in Sysmon EID 1 — they are launched as children of `cmd.exe` and do not match the sysmon-modular include-mode ProcessCreate filter patterns.

**Sysmon EID 10 — process access (4 events):** PowerShell accessing `whoami.exe` and `cmd.exe` child processes with `GrantedAccess: 0x1fffff` (tagged `technique_id=T1055.001`). These reflect the ART test framework's normal child process management.

**Sysmon EID 7 — image load (8 events):** .NET CLR components (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`) load into the PowerShell process, along with Defender components `MpOAV.dll` and `MpClient.dll`.

**Sysmon EID 17 — named pipe create (1 event):** PowerShell host pipe creation, standard artifact.

**Sysmon EID 11 — file create (1 event):** PowerShell startup profile data, standard artifact.

**PowerShell EID 4104 (103) and 4103 (2):** Script block events consist of ART test framework boilerplate. No Ghost Task-specific logic appears in script blocks.

**Comparison to the defended dataset:** The defended version recorded 16 sysmon, 10 security, and 35 powershell events. This undefended dataset records 18 sysmon, 4 security, and 105 powershell events. The defended run had more security events, likely because Defender's own processes generated EID 4688 activity. Crucially, neither version captures registry modification events (Sysmon EID 12/13), Task Scheduler events, or Security EID 4698 — in the defended run this was due to blocking; in the undefended run, the absence of registry modification events suggests either the Ghost Task writes did not succeed at the registry level, or the Sysmon configuration's registry monitoring rules do not cover the TaskCache hive writes.

The undefended dataset does demonstrate something the defended version cannot: the GhostTask.exe binary ran to completion (both `add` and `delete` commands executed), confirming the tool is not blocked when Defender is disabled.

## What This Dataset Does Not Contain

This dataset has significant gaps relative to the expected forensic footprint of a successful Ghost Task:

- No Sysmon EID 12/13 (registry create/modify) events showing writes to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`. The GhostTask technique's defining characteristic — direct registry writes — is not captured here. The sysmon-modular configuration's registry monitoring rules apparently do not cover the TaskCache path, or the writes occurred in a subprocess that was not instrumented.
- No Task Scheduler operational log events (EID 106, 140, 141). Ghost tasks are intentionally designed to avoid these, and the dataset confirms that design.
- No Security EID 4698 (scheduled task created). Also intentional by design.
- No Sysmon EID 1 events for `GhostTask.exe` or `PsExec.exe`. These binaries are invoked as children of `cmd.exe` and do not match include-mode filters.
- No evidence of the task (`lilghostie`) actually executing — no `notepad.exe` process creation, no logon trigger fired.

## Assessment

This dataset is valuable for training detection logic against the Ghost Task invocation pattern visible in process creation telemetry. The full command lines in Security EID 4688 preserve the tool names, task name, and arguments. However, it does not capture the registry artifacts that would be necessary to detect Ghost Tasks through the more evasion-resistant approach (monitoring TaskCache writes) rather than the less evasion-resistant approach (monitoring command-line activity for known tool names).

For detection engineers building rules against Ghost Task registry writes, this dataset should be supplemented with registry audit data or Sysmon configurations that explicitly include the TaskCache registry path. The dataset is suitable for command-line-based detection development and for testing whether existing scheduled task detections fire on the non-standard registry-based creation path.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` contains `GhostTask.exe` — a tool name not expected in legitimate environments. Alert on `ExternalPayloads\GhostTask.exe` or the task operation arguments (`add`, `delete`, task name).

2. The combination of `PsExec.exe \\localhost -accepteula -s` followed by `GhostTask.exe` in the same `cmd.exe` command line is a distinctive pattern: SYSTEM-level privilege escalation via PsExec chained immediately with a task manipulation tool.

3. `cmd.exe` spawned from `powershell.exe` as `NT AUTHORITY\SYSTEM` in `C:\Windows\TEMP\` is consistent with automated exploitation tooling. The working directory and integrity level together narrow the population of legitimate processes.

4. Sysmon EID 10 events with `GrantedAccess: 0x1fffff` from PowerShell to child `cmd.exe` processes, combined with the `cmd.exe` command line containing `PsExec.exe` and `GhostTask.exe`, provide a multi-event correlation anchor.

5. Although absent here, the expected detection for this technique in a properly-instrumented environment would be Sysmon EID 13 writes to `HKLM\...\Schedule\TaskCache\Tasks\` or `TaskCache\Tree\` by a process other than `svchost.exe` (the Task Scheduler service). Expanding Sysmon registry include rules to cover these paths would surface the defining artifact of Ghost Tasks.

6. The `add lilghostie` argument pattern in `GhostTask.exe` command lines — a non-default task name chosen by the operator — could serve as an indicator of a specific campaign, though production deployments would use less distinctive names.
