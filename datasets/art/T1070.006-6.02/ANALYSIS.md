# T1070.006-6: Timestomp — Modify File Last Modified Timestamp with PowerShell

## Technique Context

T1070.006 (Timestomp) encompasses adversary manipulation of NTFS file timestamps to defeat timeline-based forensic analysis. While T1070.006-5 targets the `CreationTime` attribute, this test targets `LastWriteTime` — the "last modified" timestamp most prominently displayed in Windows Explorer, `dir` command output, and most file manager tools.

The `LastWriteTime` is the timestamp that analysts and incident responders most commonly use to identify recently modified files. Timeline analysis tools (such as those built on the Windows MACB framework — Modified, Accessed, Changed, Born) prioritize `$STANDARD_INFORMATION LastWriteTime` when building execution timelines. Setting it to `01/01/1970 00:00:00` makes a file appear to have been last modified over 50 years ago, which would push it to the bottom of any recency-sorted file listing.

The PowerShell mechanism is the same as T1070.006-5: the `.LastWriteTime` property of a `FileInfo` object is assigned directly in a PowerShell inline command. The target file is the same `T1551.006_timestomp.txt` in the `ExternalPayloads` directory.

In a real attack, `LastWriteTime` modification is typically applied to malware binaries, scripts, or configuration files that were recently written to disk, making them appear to be old legitimate files when sorted by modification date. Epoch timestamp choices are an automated testing artifact — real attackers choose timestamps that blend with nearby legitimate files.

## What This Dataset Contains

The technique execution is captured in Security EID 4688 with the PowerShell command line: `"powershell.exe" & {Get-ChildItem "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1551.006_timestomp.txt" | % { $_.LastWriteTime = "01/01/1970 00:00:00" }}`. This is structurally identical to the T1070.006-5 command but targets `.LastWriteTime` rather than `.CreationTime`.

Sysmon EID 1 captures the same command with the tag `technique_id=T1059.001,technique_name=PowerShell` and the parent `powershell.exe` chain. The full path to the target file is visible in the command line.

The cleanup ART script block (`Invoke-AtomicTest T1070.006 -TestNumbers 6 -Cleanup -Confirm:$false`) is visible in PowerShell EID 4104 and as a corresponding process creation event.

PowerShell script block logging (EID 4104) captures 103 events. The ART module import and cleanup script block appear in the script block log. Sysmon EID 7 records image loads, EID 10 records process access events, and EID 17 records named pipe creation.

The dataset contains 139 total events: 103 PowerShell, 4 Security, and 32 Sysmon.

## What This Dataset Does Not Contain

As with T1070.006-5, the timestamp modification itself is not recorded as a dedicated event. There are no file metadata change events in the Security log or Sysmon for the `LastWriteTime` modification. The only evidence of the modification is the PowerShell command line.

There is no Sysmon EID 2 (file creation time changed) for `LastWriteTime` modifications — EID 2 monitors the `$STANDARD_INFORMATION $MFTModified` and `$STANDARD_INFORMATION $Created` fields but does not specifically capture `LastWriteTime` changes in all configurations.

The dataset does not confirm the modification was successful. If the file did not exist or PowerShell lacked write access, the `$_.LastWriteTime` assignment would fail silently (the command uses no error handling). The Security EID 4688 process exit code is not captured in this dataset's samples.

No network, registry, WMI, or Defender events are present.

## Assessment

This dataset is nearly identical in structure to T1070.006-5, differing only in the property being modified (`.LastWriteTime` vs. `.CreationTime`). Both techniques use the same PowerShell idiom and produce the same event profile. The difference is forensically significant: `LastWriteTime` modification attacks the most visible timestamp in standard file system browsing, while `CreationTime` modification targets what forensic tools show as the file's origin date.

Compared to the defended variant (27 Sysmon, 10 Security, 45 PowerShell), the undefended run has a similar Security count and a higher PowerShell count (103 vs. 45), consistent with ART test framework behavior. The Sysmon count is slightly higher (32 vs. 27).

The detection surface and detection gaps are identical to T1070.006-5: command-line inspection is the primary mechanism, and the absence of file metadata change events means the modification cannot be confirmed from this telemetry alone.

## Detection Opportunities Present in This Data

**PowerShell command line containing `.LastWriteTime =` assignment:** Security EID 4688 and Sysmon EID 1 capture the complete command. The pattern `$_.LastWriteTime = "..."` in a PowerShell command line targeting a specific file path is a reliable indicator. Unlike `.CreationTime`, `LastWriteTime` can be set by legitimate backup and archival tools, but those would not do so via inline PowerShell one-liners under SYSTEM context against specific files in arbitrary directories.

**Epoch or pre-Windows-era timestamps in PowerShell timestamp commands:** The value `01/01/1970 00:00:00` is the Unix epoch and is never a valid `LastWriteTime` for a Windows file created by normal system activity. Monitoring for this specific value, or for any date before Windows NT's release in 1993, in PowerShell timestamp-setting commands catches obvious timestomping.

**Behavioral comparison with T1070.006-5:** The two datasets (T1070.006-5 and T1070.006-6) together form a pair covering `CreationTime` and `LastWriteTime` modification. A complete timestomping operation would typically modify both (and also `LastAccessTime`) to make a file appear consistently old. Seeing two or more timestamp-related PowerShell commands targeting the same file in close temporal sequence is a stronger indicator than either alone.

**Sysmon EID 2 gap:** As noted in T1070.006-5: Sysmon EID 2 (file creation time changed) specifically exists to capture timestomping. This dataset demonstrates the detection coverage gap when EID 2 monitoring is not enabled or not scoped to the relevant paths. If you are validating whether your Sysmon configuration detects timestomping, this dataset provides a clear negative example against which to test EID 2 rule coverage.
