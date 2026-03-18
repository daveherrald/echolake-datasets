# T1195-1: Supply Chain Compromise — Octopus Scanner Malware Open Source Supply Chain

## Technique Context

Supply Chain Compromise (T1195) describes attacks where adversaries manipulate software or its delivery mechanisms before it reaches end users. The Octopus Scanner variant specifically targets open source software ecosystems by injecting malicious payloads into Java-based projects distributed through platforms like GitHub and Apache NetBeans. On a victim system, the malware drops a JAR file (`ExplorerSync.db`) in a camouflaged location, then establishes persistence via a scheduled task named `ExplorerSync` that runs `javaw -jar ExplorerSync.db` on a per-minute schedule. The scheduled task name and file naming (`ExplorerSync`) are designed to blend with legitimate Explorer-related activity. This ART simulation recreates the persistence mechanism without the initial compromise vector, focusing on the scheduled task creation and file staging behavior that would occur on an infected developer workstation.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the complete Octopus Scanner persistence simulation on ACME-WS06.acme.local, including file staging, scheduled task creation, and cleanup.

**Complete persistence chain in Security EID 4688:** Six process creation events document the full execution:

1. PowerShell (PID 17276) spawns `whoami.exe` — pre-execution identity check
2. PowerShell spawns `cmd.exe` with: `"cmd.exe" /c copy %temp%\ExplorerSync.db %temp%\..\Microsoft\ExplorerSync.db & schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\..\Microsoft\ExplorerSync.db" /sc MINUTE /f`
   — this single command chains the file copy and scheduled task creation
3. cmd.exe spawns `schtasks.exe` with: `schtasks  /create /tn ExplorerSync /tr "javaw -jar C:\Windows\TEMP\..\Microsoft\ExplorerSync.db" /sc MINUTE /f`
   — the resolved paths confirm `%temp%\..\Microsoft\` expands to `C:\Windows\Microsoft\`, a non-standard location
4. PowerShell spawns `whoami.exe` — post-execution identity check
5. PowerShell spawns `cmd.exe` with: `"cmd.exe" /c schtasks /delete /tn ExplorerSync /F 2>null & del %temp%\..\Microsoft\ExplorerSync.db 2>null & del %temp%\ExplorerSync.db 2>null`
   — cleanup command
6. cmd.exe spawns `schtasks.exe` with `schtasks  /delete /tn ExplorerSync /F` — explicit task deletion

**Scheduled task lifecycle — full Security audit trail:**
- **Security EID 4698:** "A scheduled task was created" — the full XML task definition is present, including task name `\ExplorerSync`, trigger interval `PT1M` (every minute), action `javaw -jar C:\Windows\TEMP\..\Microsoft\ExplorerSync.db`, creation date `2026-03-17T09:40:24`, author `ACME\ACME-WS06$`, and task GUID `{99A278C4-C196-49C9-ACF2-99C20EF0E07C}`
- **Security EID 4699:** "A scheduled task was deleted" — the cleanup deletion is recorded

**Task Scheduler channel (three events):**
- **EID 106:** `User "ACME\ACME-WS06$" registered Task Scheduler task "\ExplorerSync"` — independent confirmation of task registration
- **EID 140:** `User "ACME\ACME-WS06$" updated Task Scheduler task "\ExplorerSync"` — task modification
- **EID 141:** `User "NT AUTHORITY\System" deleted Task Scheduler task "\ExplorerSync"` — cleanup deletion (note the System account deletion during cleanup vs. the machine account creation)

**Sysmon EID 1 — full process tree captured:**
- `whoami.exe` (PID 18352) from PowerShell — identity check
- `cmd.exe` (PID 17452) with the full chained copy-and-schtasks command — tagged `RuleName: technique_id=T1059.003,technique_name=Windows Command Shell`
- `schtasks.exe` (PID 17680) with the task creation arguments — tagged `RuleName: technique_id=T1053.005,technique_name=Scheduled Task/Job`

**Sysmon EID 12 — registry artifact:**
- A `DeleteKey` event for `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\ExplorerSync` captured by `svchost.exe` (PID 1964) — the Task Scheduler service cleaning the registry entry on task deletion

**Sysmon EID 13 — registry value writes:** Three registry value write events to the `\Schedule\TaskCache\Tree\ExplorerSync\` key recording Index, Security Descriptor, and Task ID — the Task Scheduler service's internal bookkeeping for the newly registered task. These are captured in the full dataset's 31 Sysmon events.

**Sysmon EID 11 — file artifacts:** Two file creation events recording `C:\Windows\Temp\null` (from cmd.exe's `2>null` output redirection during cleanup) — confirming the cleanup phase executed.

Compared to the defended dataset (23 Sysmon, 13 Security, 35 PowerShell, plus 3 Task Scheduler events), this undefended run has more events (31 Sysmon, 8 Security, 108 PowerShell, 3 Task Scheduler). The additional Security events are the key difference: the defended dataset captured only 13 Security events and described capturing EID 4698/4699; this undefended run confirms all the same scheduled task lifecycle events plus a richer PowerShell log.

## What This Dataset Does Not Contain

**Initial supply chain infection vector:** The actual `ExplorerSync.db` JAR file that would contain the malicious Java payload is not present — the ART test simulates the post-infection persistence behavior only. No file download or initial compromise activity appears.

**javaw.exe execution:** If the scheduled task had fired before cleanup, a `javaw.exe` process running `ExplorerSync.db` would appear in process creation logs. The test creates and immediately deletes the task, so javaw.exe never executes.

**Network activity:** No Sysmon EID 3 or EID 22 events appear; this simulation is entirely local and involves no network communication.

**C2 or data exfiltration:** The real Octopus Scanner malware would make callbacks to command and control infrastructure. No such activity is simulated or present in this dataset.

## Assessment

This dataset provides excellent multi-source telemetry for detecting the scheduled task persistence pattern associated with Octopus Scanner. The combination of Security EID 4698 with the full XML task definition, Task Scheduler EID 106, and Sysmon EID 1 capturing `schtasks.exe` with its exact arguments gives three independent detection paths for the same persistence mechanism.

The `javaw -jar` scheduled task action is particularly distinctive: legitimate Java applications rarely register scheduled tasks via schtasks.exe from PowerShell, and the file path `C:\Windows\TEMP\..\Microsoft\ExplorerSync.db` (a JAR file placed in `C:\Windows\Microsoft\`) is an unusual and suspicious location. The task name `ExplorerSync` is designed to blend in, but the task action, creation process lineage, and file location together form a coherent behavioral cluster.

Security EID 4698 with the full task XML is the highest-fidelity single event in this dataset: the complete task definition including trigger interval, action binary, and author account is preserved, making retrospective investigation straightforward even after the task is deleted.

## Detection Opportunities Present in This Data

- **Security EID 4698:** Scheduled task created with action `javaw -jar [path].db` — `javaw` executing a `.db`-extension file as a JAR is highly anomalous; the task XML also exposes the per-minute trigger interval, non-standard file path, and task name
- **Task Scheduler EID 106:** Task `\ExplorerSync` registered — the task name is camouflage, but any unexplained task registration on a workstation warrants investigation
- **Sysmon EID 1:** `schtasks.exe` with `/create /tn ExplorerSync /tr "javaw -jar ..."` — tagged `T1053.005` by Sysmon-modular; the `/sc MINUTE /f` flags (per-minute, force creation) are anomalous for legitimate software
- **Security EID 4688:** The chained cmd.exe command combining file copy and schtasks creation is a behavioral signature of the Octopus Scanner persistence pattern; `copy` to `%temp%\..\Microsoft\` is an unusual staging location
- **Sysmon EID 12/13:** Registry modifications to `\Schedule\TaskCache\Tree\ExplorerSync` by the Task Scheduler service provide a third independent confirmation of task registration, separate from Security and Task Scheduler channels
- **Cleanup detection:** Immediate deletion (EID 4699, Task Scheduler EID 141) following creation within the same session is an ART artifact, but also mirrors attacker anti-forensic behavior worth tracking as a behavioral pattern
