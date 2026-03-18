# T1003.003-3: NTDS — Dump Active Directory Database with NTDSUtil

## Technique Context

T1003.003 (NTDS) targets the Active Directory database file to extract all domain credential hashes. NTDSUtil is Microsoft's own utility for managing Active Directory Domain Services — it is used legitimately for database maintenance, defragmentation, and creating Install From Media (IFM) sets. The IFM feature is designed to allow setting up new domain controllers without a full replication, but attackers repurpose it to create a copy of NTDS.dit and the associated registry hives in an accessible location.

The attack command is essentially: `ntdsutil "ac i ntds" "ifm" "create full c:\some\output\path" q q`. This creates a complete backup of the AD database at the specified path, including NTDS.dit and the SYSTEM/SECURITY/SAM hives needed for offline credential extraction. Because NTDSUtil is a legitimate Microsoft binary that is expected on domain controllers, detecting it requires behavioral context rather than simple binary allow/block decisions.

This test runs on a domain **workstation** (ACME-WS06), not a domain controller. NTDSUtil's IFM feature requires AD DS to be installed — on a workstation without AD DS, the command will fail. However, the attempt still generates telemetry from the process creation and the NTDSUtil execution itself. The dataset captures what this looks like on a workstation, which is itself suspicious since NTDSUtil IFM use is not a legitimate workstation activity.

## What This Dataset Contains

This dataset was collected from ACME-WS06 (Windows 11 Enterprise Evaluation, `acme.local` domain) with Windows Defender disabled. Execution was as `NT AUTHORITY\SYSTEM`.

**Security channel (420 events: 409x EID 4664, 7x EID 5379, 4x EID 4688):** The 409 EID 4664 events dominate this dataset and are entirely unrelated to the NTDSUtil attempt — EID 4664 records hard link creation attempts, and this count reflects intensive Windows Update and installer activity running concurrently. This is the highest Security channel event count in the entire T1003.003 batch. The 4 EID 4688 events show the meaningful activity: `powershell.exe` spawning two `whoami.exe` instances (PIDs 0x16c0 and 0x15c0, the ART pre- and post-checks), and `cmd.exe` (PID 0x564) for the NTDSUtil execution. The absence of `ntdsutil.exe` in the EID 4688 samples (it would be a child of cmd.exe) suggests either the NTDSUtil process wasn't captured in the 20-event sample or the command was passed inline.

**Sysmon channel (57 events: 47x EID 11, 4x EID 1, 4x EID 10, 1x EID 17, 1x EID 7):** The Sysmon EID 1 process creation events do not show NTDSUtil specifically in the 20-event sample — they show `whoami.exe` (pre/post checks) and `cmd.exe`. The 47 EID 11 file creation events are again dominated by Windows Update, InstallService, and Delivery Optimization artifacts running during the test window. The EID 17 named pipe creation for `\PSHost.134180019867776303.5964.DefaultAppDomain.powershell` identifies the driving PowerShell session (PID 5964).

**PowerShell channel (105 events: 103x EID 4104, 2x EID 4103):** The ART test framework events are present. The 2 EID 4103 module logging events are consistent with the other T1003.003 tests.

**Compared to the defended dataset (sysmon: 25, security: 10, powershell: 41):** The Security channel is dramatically larger undefended (420 vs. 10 events). However, this is almost entirely driven by the 409 EID 4664 events from background Windows Update activity — not from the NTDSUtil execution itself. The Sysmon count is higher (57 vs. 25), again mostly driven by background file creation. PowerShell events are higher (105 vs. 41), indicating the complete ART test framework executed without Defender interruption. The key difference: in the defended run, Defender may have blocked the cmd.exe/NTDSUtil invocation before it executed; here, the command ran (and likely failed gracefully on the workstation).

## What This Dataset Does Not Contain

NTDSUtil's actual execution — the `ntdsutil.exe` process creation — is not in the 20-event sample. It would appear as an EID 1 event with a command line containing `ntdsutil`, `"ac i ntds"`, or `"ifm"`. The output directory creation and NTDS.dit file copy artifacts (if they succeeded) would appear as EID 11 events but are not in the sample. Since this ran on a workstation rather than a domain controller, NTDSUtil's IFM operation would fail with an error about AD DS not being installed — the telemetry captures the attempt but the credential material was not extracted. Registry access audit events (EID 4656/4663) for the AD database are absent.

## Assessment

This dataset is complicated by the heavy background EID 4664 activity that inflates the Security channel to 420 events. The actual NTDSUtil execution telemetry is present in the full dataset but is sparse in the sample. The most useful aspects of this dataset are: (1) confirming what NTDSUtil execution from a PowerShell-as-SYSTEM context looks like in EID 4688 and Sysmon EID 1, and (2) documenting the EID 4664 background activity pattern that can mask legitimate attack telemetry in Security logs. Detection engineers should be aware that heavy EID 4664 activity can obscure the 4 meaningful EID 4688 events in this Security log.

## Detection Opportunities Present in This Data

1. **EID 4688 / Sysmon EID 1 — ntdsutil.exe process creation:** `ntdsutil.exe` appearing in a process creation event on a workstation (as opposed to a domain controller) is highly suspicious. The full command line should include `ac i ntds` (activate instance ntds) and `ifm` (Install From Media) arguments.

2. **EID 4688 — ntdsutil.exe parent process:** NTDSUtil being spawned by `cmd.exe` which was itself spawned by `powershell.exe` running as SYSTEM is not a legitimate administrative workflow. Real NTDSUtil IFM operations are typically run interactively on domain controllers.

3. **Sysmon EID 11 — IFM output directory creation:** When NTDSUtil's IFM operation succeeds (on a DC), it creates an output directory with subdirectories `Active Directory\` and `registry\`. Monitoring for these subdirectory patterns in unexpected locations is a direct artifact.

4. **Security EID 4664 volume anomaly:** While EID 4664 events are mostly background activity here, a sudden spike in hard link creation attempts (409 events in a short window) coinciding with other suspicious activity can indicate overall system instability or aggressive installer/update behavior that may mask attack activity.

5. **EID 4688 — workstation executing AD management tools:** Any execution of `ntdsutil.exe`, `dsdbutil.exe`, or `ndtsutil.exe` on a non-DC machine (hostname not ending in `-DC`, `-DC0X`, or identified via AD role) is an immediate anomaly worth investigating.

6. **PowerShell EID 4103/4104 — volume anomaly as SYSTEM:** 105 events from a single test window running as NT AUTHORITY\SYSTEM on a workstation is well above baseline. Pairing this with any AD-related tool execution provides context for the activity.
