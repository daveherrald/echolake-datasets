# T1070.006-5: Timestomp — Modify File Creation Timestamp with PowerShell

## Technique Context

T1070.006 (Timestomp) covers adversary manipulation of file timestamps — the Modified, Accessed, Created, and Entry (MACE) timestamps recorded in NTFS metadata for every file. Forensic analysis frequently relies on timestamps to reconstruct timelines: when a file appeared on a system, when it was last written, and when it was last accessed. By setting a file's creation timestamp to a historical date, an attacker can make a recently placed tool or payload appear to have existed on the system long before the intrusion.

This test uses PowerShell's `.CreationTime` property on a `FileInfo` object to set the creation timestamp of `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt` to `01/01/1970 00:00:00` — the Unix epoch. The choice of the Unix epoch is characteristic of automated testing rather than a realistic attacker timestamp choice, which would typically be set to a date consistent with legitimate system file timestamps.

The NTFS timestamp `.CreationTime` is one of four timestamps tracked per file. Modifying only `CreationTime` (as opposed to `LastWriteTime` or `LastAccessTime`) is a specific forensic evasion choice: it affects what an analyst sees when looking at "file created" columns in file system timelines.

This technique does not require elevated privileges — any user with write access to the file can modify its timestamps. In this test, execution is under `NT AUTHORITY\SYSTEM` via the ART test framework.

Both the defended and undefended variants completed without interference.

## What This Dataset Contains

The technique evidence is in the PowerShell process creation events. Security EID 4688 records the PowerShell launch with command line: `"powershell.exe" & {Get-ChildItem "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt" | % { $_.CreationTime = "01/01/1970 00:00:00" }}`. This command uses `Get-ChildItem` to retrieve the `FileInfo` object and a `ForEach-Object` (aliased as `%`) block to set the `.CreationTime` property to `01/01/1970 00:00:00`.

Sysmon EID 1 captures the same command line with the tag `technique_id=T1059.001,technique_name=PowerShell`, with parent `powershell.exe` (the ART orchestration process).

The ART cleanup phase appears as a separate PowerShell process invocation in Security EID 4688 and Sysmon EID 1: the cleanup script block `try { Invoke-AtomicTest T1070.006 -TestNumbers 5 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}` is visible in the EID 4104 log.

PowerShell script block logging (EID 4104) captures 103 events. The ART module import and cleanup script block appear in the script block log. The technique payload itself is in the process creation event command lines rather than as a distinct 4104 entry.

Sysmon EID 10 records process access events (PowerShell opening other processes with mask `0x1FFFFF`). Sysmon EID 7 records image loads for the PowerShell process. Sysmon EID 17 records named pipe creation for the PowerShell host.

The dataset contains 140 total events: 103 PowerShell, 4 Security, and 33 Sysmon.

## What This Dataset Does Not Contain

The timestamp modification itself is not directly captured as an event. Windows does not generate a native event log entry when a file's NTFS timestamps are modified via the `FileInfo` object's properties or the `SetFileTime` API. There is no Security EID 4663 (because file object access auditing was not enabled) and no Sysmon event type for timestamp modification (Sysmon captures file creation, deletion, and content changes, but not timestamp-only modifications).

The dataset does not contain the original or modified timestamp values as event fields. You can infer from the command line that the creation timestamp was set to `01/01/1970 00:00:00`, but this is not verified by a file metadata event.

The target file's content, original timestamps, or context (what it represents in the attack simulation) are not present in the event data.

No Defender events, network activity, registry changes, or WMI events are present.

## Assessment

The timestamp modification technique leaves minimal telemetry because NTFS timestamp changes via PowerShell property assignment are not logged as dedicated events. The primary detection surface is the PowerShell command line itself — which is comprehensively captured in this dataset via Security EID 4688 and Sysmon EID 1.

Compared to the defended variant (26 Sysmon, 10 Security, 36 PowerShell), the undefended run has the same Security event count and a higher PowerShell count (103 vs. 36), consistent with the ART test framework behavior across this series. The Sysmon count is slightly higher (33 vs. 26). There is no meaningful behavioral difference between the variants — Defender neither detected nor blocked the timestamp modification in either environment.

The key insight for this dataset is that the entire detection surface is the command line. There is no secondary event confirming the modification occurred at the OS level. A detection system relying on detecting the timestamp change itself (rather than the PowerShell command that performed it) would find no signal here.

## Detection Opportunities Present in This Data

**PowerShell command line containing `.CreationTime =` assignment:** Security EID 4688 and Sysmon EID 1 capture the complete command. The pattern `$_.CreationTime = "..."` or `(Get-Item ...).CreationTime = "..."` in a PowerShell command line is a reliable indicator — setting a file's creation time programmatically has very few legitimate uses, and none that would appear as an inline PowerShell one-liner under SYSTEM context.

**Epoch timestamp value in command line:** The target timestamp `01/01/1970 00:00:00` is the Unix epoch — a value that should never appear as a legitimate Windows file creation timestamp. Monitoring for this specific string, or for any date prior to the Windows NT era (pre-1993) appearing in PowerShell timestamp-setting commands, can catch obvious timestomping activity.

**`Get-ChildItem` piped into timestamp property assignment:** The specific pattern `Get-ChildItem <path> | % { $_.CreationTime = ... }` (or with `ForEach-Object`) identifies the PowerShell timestamp modification idiom. Variations include `(Get-Item <path>).CreationTime = ...`. Both resolve to the same underlying API call.

**Absence of a Sysmon file modification event correlated with process execution:** If you observe a PowerShell process with timestamp-setting content in its command line, you can look for the file that was targeted and examine its current timestamps out-of-band. The absence of a corresponding file write event (Sysmon EID 2 for file creation time changed exists in some Sysmon configs) while a timestamp modification command ran is itself informative about the limitations of your telemetry coverage.

**Note on Sysmon EID 2:** Sysmon provides EID 2 (file creation time changed) specifically to detect timestomping. If EID 2 monitoring were enabled and targeted the `ExternalPayloads` directory, it would directly record the creation time being changed to `1970-01-01`. This dataset demonstrates the detection gap that exists without EID 2 monitoring in place.
