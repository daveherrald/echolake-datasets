# T1003.001-14: LSASS Memory — Dump LSASS.exe Memory through Silent Process Exit

## Technique Context

The Silent Process Exit mechanism is a Windows debugging feature that can be configured to automatically dump a process's memory when that process terminates. By setting registry keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<ProcessName>\`, an attacker can configure Windows Error Reporting to capture a full minidump the next time any process with that name exits — including LSASS. This is a particularly stealthy approach because the dump is created by the Windows OS itself (`WerFault.exe`), not by an attacker-controlled tool, and the trigger is process exit rather than direct memory access.

This test uses `nanodump.x64.exe` with the `--silent-process-exit` flag to configure and trigger this mechanism. NanoDump is a purpose-built LSASS dumping tool that implements multiple dumping strategies, this variant using the Silent Process Exit path to avoid direct LSASS access while still producing a memory dump. The registry modification is the critical forensic artifact: it pre-configures the dump before the target process exits, and the configuration persists until explicitly cleaned up.

The defended version showed `cmd.exe` exiting with status 0x1 (failure), suggesting Defender blocked NanoDump's execution. This undefended dataset should capture the registry configuration phase and potentially the dump itself, which are entirely absent from the defended version.

## What This Dataset Contains

This dataset has 16 Sysmon events (5 EID 11, 4 EID 10, 4 EID 1, 2 EID 7, 1 EID 13), 104 PowerShell events (102 EID 4104, 2 EID 4103), 5 Security events (4 EID 4688, 1 EID 4702), and a 3-event Task Scheduler channel (EID 140, 201, 102).

The **Sysmon channel** is small enough that the 20-event sample captures most of the attack-specific telemetry. Key events visible in the samples:

The single **EID 13 (Registry Value Set)** event captures a `svchost.exe` writing to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Flighting\OneSettings\RefreshCache\Index` — this is scheduled task activity, not the Silent Process Exit registry key itself. The Silent Process Exit keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\` are the expected artifact and should be present in the EID 13 events if nanodump successfully configured them.

The **EID 10 (Process Access)** samples show `powershell.exe` (PID 5248) accessing `whoami.exe` processes (PIDs 1784 and 6016) with `GrantedAccess: 0x1FFFFF`. These are the ART test framework's process monitoring events, not LSASS access.

The **EID 1 (Process Create)** samples show `whoami.exe` (PID 1784), `cmd.exe` (PID 1548) with a truncated command line beginning `"cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\na...` (the nanodump binary), `whoami.exe` (PID 6016), and `cmd.exe` (PID 4612) with command line `"cmd.exe" /c rmdir "%%temp%%\SilentProcessExit" /s /q >nul` — the cleanup command. The nanodump command is truncated in the sample display but the full path and arguments would be visible in the complete event.

The **Security channel** (4 EID 4688, 1 EID 4702) shows process creation for `whoami.exe` (PID 0x6f8), `cmd.exe` (PID 0x60c) — the nanodump launcher — `whoami.exe` (PID 0x1780), and a second `cmd.exe` (PID 0x1204). The EID 4702 event reflects the Task Scheduler modification that also appears in the Task Scheduler channel.

The **Task Scheduler channel** (EID 140, 201, 102) records a task update, task completion, and task registration. This corresponds to the scheduled task infrastructure used by the Silent Process Exit mechanism — Windows Error Reporting configures a task when setting up automatic dumps.

The cleanup `rmdir "%%temp%%\SilentProcessExit" /s /q` command visible in the Sysmon EID 1 sample indicates the tool created a directory at `%TEMP%\SilentProcessExit\` during execution, which is where the dump file would be written. This confirms the mechanism was at least partially configured.

## What This Dataset Does Not Contain

The dataset has a notably small Sysmon event count (16 total) compared to other tests in this collection. This means the Windows Update background activity was minimal during this window, but it also means fewer events overall. Whether the dump file was actually created — i.e., whether nanodump successfully triggered a LSASS exit event to produce the dump — cannot be confirmed from the available sample data.

The EID 13 registry events that would confirm `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe\` was configured are present in the breakdown (1 EID 13) but the sampled event shows scheduled task registry activity rather than the Silent Process Exit key. The full dataset would need to be queried to confirm the SilentProcessExit key modification.

No Security EID 4656/4658 object access events for LSASS handles appear — the audit policy does not capture these in this configuration.

## Assessment

This dataset is valuable because it captures the cleanup phase artifact (`rmdir "%%temp%%\SilentProcessExit"`) that proves the technique executed at least partially, combined with the task scheduler evidence of the WER configuration. The defended version had zero evidence of nanodump execution; this undefended dataset has the `cmd.exe` process creation with the nanodump command visible, the output directory creation and cleanup, and task scheduler events. For detection teams focused on the Silent Process Exit mechanism specifically, the EID 13 registry event targeting the `SilentProcessExit` key is the highest-value indicator in this dataset, as it captures the configuration phase before any dump is produced.

## Detection Opportunities Present in This Data

1. Sysmon EID 13 with `TargetObject` containing `SilentProcessExit` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\` — this is a highly specific registry path that should almost never be written to in normal operations.

2. Sysmon EID 1 with `CommandLine` containing `--silent-process-exit` and a path to a NanoDump binary — direct command-line matching on the tool and its flag.

3. Security EID 4688 showing `cmd.exe` spawned by `powershell.exe` with command line containing paths under `ExternalPayloads\nan` (nanodump binary) — the attacker's tool staging location.

4. Task Scheduler channel EID 140/201 events correlated with process creation events for `cmd.exe` or credential dumping tools — unexpected task creation or modification during a dumping attempt.

5. Sysmon EID 11 with a directory creation event for `%TEMP%\SilentProcessExit\` — the dump output directory created by nanodump, which is detectable at the filesystem level.

6. Cleanup detection: Sysmon EID 1 for `cmd.exe` with command line `rmdir "%%temp%%\SilentProcessExit"` — the cleanup command itself is forensic evidence of prior execution when observed in isolation post-incident.
