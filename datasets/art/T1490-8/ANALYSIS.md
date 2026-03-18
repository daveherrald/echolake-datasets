# T1490-8: Inhibit System Recovery — Disable the SR Scheduled Task

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) includes disabling the System Restore scheduled task as a lightweight, low-noise method of preventing automatic recovery point creation. The System Restore (SR) task at `\Microsoft\Windows\SystemRestore\SR` triggers periodic restore point snapshots. Disabling it prevents Windows from creating new restore points going forward, without requiring shadow copy deletion or backup catalog destruction. This technique is favored when an attacker wants to degrade recovery capability without triggering VSS-based detections. It is often combined with VSC deletion: the SR task is disabled to prevent new restore points from accumulating during an extended dwell period, then shadows are deleted immediately before encryption.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The chain is captured completely: `cmd.exe /c schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable` → `schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable`. The `cmd.exe` wrapper is tagged `technique_id=T1059.003` and `schtasks.exe` is tagged `technique_id=T1053.005,technique_name=Scheduled Task/Job`. Both run as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

**Sysmon (Event ID 13) — RegistryEvent:**
A registry value set event is captured: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\SystemRestore\SR\Index` is written by `svchost.exe` (Task Scheduler service, PID 2316). The value type is `DWORD (0x00000003)`. This is the Task Scheduler's internal bookkeeping update reflecting the state change — the SR task `Index` field encodes the task's enabled/disabled status. This registry event provides an independent, non-process-based detection anchor.

**Task Scheduler (Event ID 142):**
`User "System" disabled Task Scheduler task "\Microsoft\Windows\SystemRestore\SR"` — this is a direct, human-readable confirmation that the System Restore scheduled task was disabled. EID 142 is the `Microsoft-Windows-TaskScheduler/Operational` event for task disablement.

**Security (Event IDs 4688/4689/4703):**
Standard process telemetry. `schtasks.exe` exits with `0x0` (success). Token right adjustment (4703) for the `schtasks.exe` process confirms privilege usage during the task modification.

**PowerShell channel:** Contains only `Set-StrictMode` and `Set-ExecutionPolicy -Bypass` test framework boilerplate. No technique content.

## What This Dataset Does Not Contain

- **Task Scheduler EID 141 (task deleted)** is absent — the task was disabled, not deleted. EID 142 (disabled) is present and is the correct event for this action.
- **No Task Scheduler EID 100/200/201** (task registered/run/finished) — the SR task itself does not execute during this window.
- **No Sysmon EID 1 for the `svchost.exe` Task Scheduler service** modifying the registry key — that process was already running and its creation is not re-logged by include-mode filtering.
- **No security EID 4698/4699/4700/4701** (task created/deleted/enabled/disabled via Security audit policy). Object access auditing is `none` in this environment, so the Security channel task-specific audit events are absent. These would be highly valuable additions in a real detection environment.

## Assessment

This dataset is well-suited for the scheduled task disablement detection use case. Three independent data sources confirm the action: Sysmon EID 1 (process create with full command line), Sysmon EID 13 (registry write in the TaskCache tree), and Task Scheduler EID 142 (task disabled). The registry event is particularly valuable because it enables detection without relying on process or command-line monitoring — useful for environments where command-line auditing is unavailable. The absence of Security channel task audit events (4700/4701) is the primary gap; enabling `Audit Other Object Access Events` would close it. Defenders should note that `schtasks /Change /TN ... /disable` is a legitimate administrator operation outside ransomware contexts, so behavioral context (SYSTEM account, TEMP directory, proximity to other T1490 commands) matters for the detection decision.

## Detection Opportunities Present in This Data

1. **Task Scheduler EID 142 — System Restore task (`\Microsoft\Windows\SystemRestore\SR`) disabled** — the highest-confidence single event; SR task disablement has a narrow set of legitimate uses.
2. **Sysmon EID 1 — `schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable`** — exact argument match; Sysmon tags this as T1053.005.
3. **Security EID 4688 — `schtasks.exe` command line with `/TN "\Microsoft\Windows\SystemRestore\SR" /disable`** — independent of Sysmon via command-line auditing.
4. **Sysmon EID 13 — registry write to `HKLM\...\TaskCache\Tree\Microsoft\Windows\SystemRestore\SR\Index`** — a registry-level indicator that does not depend on process monitoring; useful for detecting indirect task disablement via registry manipulation.
5. **Process chain** `cmd.exe → schtasks.exe` launched from `C:\Windows\TEMP\` as SYSTEM — the execution context distinguishes attacker use from legitimate sysadmin task management.
6. **Temporal correlation** — disabling SR immediately followed by (or preceding) shadow copy deletion or bcdedit modifications elevates confidence substantially.
