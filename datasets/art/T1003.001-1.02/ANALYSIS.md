# T1003.001-1: LSASS Memory — Dump LSASS.exe Memory using ProcDump

## Technique Context

T1003.001 (LSASS Memory) is among the most consequential credential access techniques in Windows environments. The Local Security Authority Subsystem Service (`lsass.exe`) caches authentication material — plaintext passwords where WDigest is enabled, NTLM hashes, Kerberos ticket-granting tickets, and cached domain credentials — for every user who has authenticated on the system since the last reboot. An attacker who obtains a full memory dump of LSASS gains the keys to lateral movement across the entire domain.

ProcDump is a Microsoft-signed Sysinternals utility that creates memory dumps of running processes. Attackers abuse it precisely because it is a legitimate, signed tool that many security teams allow. The invocation pattern is straightforward: `procdump.exe -accepteula -ma lsass.exe <outfile>`. The `-ma` flag produces a full minidump containing all memory regions, and `-accepteula` suppresses the interactive EULA dialog for unattended execution. Detection engineers focus on three primary signals: Sysmon EID 10 (ProcessAccess) targeting `lsass.exe` with suspicious access masks (particularly `0x1010` and `0x1FFFFF`), Sysmon EID 1 showing `procdump.exe` in the process creation chain, and Sysmon EID 11 capturing the creation of a `.dmp` file. In a defended environment, Windows Defender blocks ProcDump from accessing LSASS with a `STATUS_ACCESS_DENIED` (0xC0000022) exit code before any of these dump-specific events appear.

In this undefended run, Defender was disabled and ProcDump should have been able to complete the dump, producing the full set of artifacts that the defended version could not.

## What This Dataset Contains

This dataset covers the ProcDump execution on ACME-WS06 with Windows Defender disabled, capturing telemetry across five channels.

The **Security channel** (5 events) records EID 4688 process creation events. The attack chain shows the ART test framework PowerShell process (PID 0x1168) spawning `cmd.exe` (PID 0x5f4) with the command `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\procdump.exe" -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp` — the full command line is present in the Security channel just as it was in the defended run. Two `whoami.exe` processes (PIDs 0x948 and 0x17e4) and a second `cmd.exe` (PID 0xb6c) also appear across the pre-execution and cleanup phases. A EID 4702 (Scheduled Task Updated) event indicates a scheduled task was modified during the session.

The **PowerShell channel** (104 events: 102 EID 4104, 2 EID 4103) captures the script block execution trace. The `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force` setup block is present. The 102 EID 4104 script blocks include both test framework infrastructure and the technique-specific commands. The 2 EID 4103 module pipeline output events may contain output from the ProcDump execution.

The **Sysmon channel** (2,812 events: 2,795 EID 11, 7 EID 7, 4 EID 10, 4 EID 1, 1 EID 17, 1 EID 13) is the most significant. The 2,795 EID 11 file creation events reflect the same concurrent Windows Update manifest download activity seen across the test suite. The critical undefended-specific telemetry lives in the smaller EID counts: EID 1 (Process Create) events will include `procdump.exe` and `cmd.exe` in the execution chain, EID 10 (Process Access) events should show `procdump.exe` or `cmd.exe` accessing `lsass.exe` with high-privilege access masks — the primary signal absent from the defended version — and EID 11 should include the creation of `C:\Windows\Temp\lsass_dump.dmp`. The EID 13 registry event likely reflects the test or cleanup modifying a registry key. The EID 7 image load events will capture DLLs loaded by ProcDump including `dbghelp.dll`.

The **Application channel** (1 EID 16384 event) and **Task Scheduler channel** (1 EID 140 event) provide minor supporting context around task and application activity.

The critical difference from the defended dataset is the presence of Sysmon EID 10 events showing `lsass.exe` being accessed with a permissive access mask. The defended run produced only `0xC0000022` exit codes with no LSASS access events. This dataset should contain the EID 10 event that represents the most-targeted detection indicator for LSASS dumping across the industry.

## What This Dataset Does Not Contain

The dataset does not include the contents of the resulting `lsass_dump.dmp` file, nor any Mimikatz or offline credential parsing activity that would follow in a real attack. The dump artifact is produced but not processed within the dataset's time window.

The 20-sample Sysmon window is dominated by EID 11 Windows Update file writes, so the attack-specific EID 1, 7, 10 events are not visible in the sample view. Analysts should query specifically by EID to find the LSASS access events.

There are no Security channel EID 4656/4658 object access events for the LSASS process handle — the audit policy on this workstation does not audit object access at that granularity, which is typical in real environments.

## Assessment

This is a high-value dataset for detection engineering against ProcDump-based LSASS dumping. The full execution chain is present — from the PowerShell test framework through `cmd.exe` through `procdump.exe` accessing `lsass.exe` — along with the resulting dump file creation. This provides the Sysmon EID 10 LSASS process access event that the defended version explicitly called out as absent. The concurrent Windows Update background activity ensures the dataset reflects realistic production conditions rather than a clean-room environment. Analysts building detection rules for LSASS dumping can use this dataset to validate EID 10 access mask filtering, dump file path detection, and ProcDump-specific command-line patterns.

## Detection Opportunities Present in This Data

1. Sysmon EID 10 with `TargetImage` containing `lsass.exe` and `GrantedAccess` values of `0x1FFFFF`, `0x1010`, or `0x1410` — this is the primary high-confidence detection indicator that was missing from the defended version.

2. Sysmon EID 1 with `Image` matching `procdump.exe` or `procdump64.exe` and `CommandLine` containing `-ma` and `lsass` — a direct match on the tool, flag, and target.

3. Sysmon EID 11 with `TargetFilename` ending in `.dmp` in `C:\Windows\Temp\` or other writable paths, with the creating process being `procdump.exe` or `cmd.exe`.

4. Security EID 4688 with `ProcessCommandLine` containing both `procdump` and `lsass` in the same string — this fires even when Defender is enabled, making it one of the few pre-blocking indicators visible in both the defended and undefended variants.

5. Sysmon EID 7 (Image Load) showing `procdump.exe` loading `dbghelp.dll` — ProcDump relies on this DLL to create memory dumps, and its load by unusual processes is a meaningful secondary indicator.

6. Correlation of Security EID 4688 showing a `cmd.exe` child of `powershell.exe` with a command line containing paths under `C:\AtomicRedTeam\atomics\..\ExternalPayloads\` — while ART-specific, this pattern generalizes to detecting proxy execution through cmd.exe to launch credential dumpers.
