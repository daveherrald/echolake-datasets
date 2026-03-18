# T1070.004-5: File Deletion — Delete an Entire Folder Using Windows cmd

## Technique Context

T1070.004 (File Deletion) covers adversary actions to remove files and directories to eliminate evidence of their activities. Deleting entire directory trees is a common post-exploitation cleanup step: after staging tools, executing payloads, or collecting data into a staging directory, an attacker can remove the entire folder hierarchy with a single `rmdir` command rather than individually deleting files.

The Windows command `rmdir /s /q` recursively removes a directory and all its contents, suppressing the confirmation prompt (`/q` for quiet mode). This is a native operating system capability present on every Windows installation, requiring no third-party tools. Because it is a standard administrative operation, it is not inherently blocked by endpoint controls.

This test targets `%TEMP%\deleteme_T1551.004`, a directory created by the ART test framework to simulate an attacker-created staging directory. The technique demonstrates the cleanup phase of an attack lifecycle — removing artifacts after their purpose has been served.

In the defended variant, Defender was active and did not block the deletion. The undefended dataset captures the same operation without endpoint controls.

## What This Dataset Contains

The core technique evidence is Security EID 4688 recording `cmd.exe` being launched with the full command line: `"cmd.exe" /c rmdir /s /q %temp%\deleteme_T1551.004`. This is the direct deletion command, executed by the ART orchestration PowerShell process. The `%temp%` variable expansion shows this is targeting the system-level temp directory under `NT AUTHORITY\SYSTEM`.

Sysmon EID 1 captures the same `cmd.exe` launch with the expanded command line: `"cmd.exe" /c rmdir /s /q %%temp%%\deleteme_T1551.004`. Sysmon tags this with `technique_id=T1083,technique_name=File and Directory Discovery` — a Sysmon rule false-positive that tags many `cmd.exe` invocations; the actual technique is T1070.004. The process tree shows `powershell.exe` (the ART orchestration process) as the parent.

Security EID 4688 also records a second `cmd.exe` invocation (`"cmd.exe" /c`) with an empty body, which corresponds to the ART cleanup phase (no cleanup action was required for this test).

Two `whoami.exe` EID 4688 entries bracket the technique execution — standard ART pre-check and post-check behavior, both with command line `"C:\Windows\system32\whoami.exe"` and parent `powershell.exe`.

PowerShell script block logging (EID 4104) captures 104 events, predominantly internal PowerShell runtime script blocks. The meaningful technique content is in the Sysmon EID 1 and Security EID 4688 command lines rather than standalone script block entries.

Sysmon EID 17 (named pipe create) and EID 7 (image loaded) provide supporting context for the PowerShell and cmd.exe execution environment. The dataset spans a narrow time window and contains 126 total events: 104 PowerShell, 4 Security, and 18 Sysmon.

## What This Dataset Does Not Contain

There are no file deletion audit events. Windows object access auditing for file deletions requires specific SACL entries on the affected directory, which were not configured on the `%TEMP%` directory. You can confirm the deletion command ran, but not enumerate which specific files within the directory were removed.

There are no Sysmon EID 23 (file deleted) or EID 26 (file delete detected, archived) events. While Sysmon can capture file deletion events when configured to do so, this dataset's Sysmon configuration does not include file delete monitoring for temporary directory paths.

No network activity is present. The `rmdir` operation is local and generates no DNS or network events.

The dataset does not include directory enumeration events showing what the `deleteme_T1551.004` directory contained before deletion. The contents were created by a prerequisite ART step and their specific filenames are not captured here.

No Defender quarantine, behavioral block, or alert events are present.

## Assessment

This is a clean capture of a recursive directory deletion via `cmd.exe`. The command line evidence is unambiguous in both Security EID 4688 and Sysmon EID 1, and the parent process chain (PowerShell → cmd.exe) is fully recorded. The technique completed successfully — the directory was deleted.

Compared to the defended variant (34 Sysmon, 10 Security, 35 PowerShell), the undefended run has more PowerShell script block events (104 vs. 35) but similar Security and slightly fewer Sysmon events (18 vs. 34). The elevated PowerShell EID 4104 count in the undefended run reflects the same ART test framework behavior documented across this dataset series — more script block recording under certain execution conditions — rather than any behavioral difference in the technique itself.

The notable gap in this dataset is the absence of file deletion telemetry for the contents of the removed directory. If the staging directory contained files of investigative interest (payloads, credential dumps, collected data), their removal is evidenced only by the `rmdir` command, not by individual file deletion records.

## Detection Opportunities Present in This Data

**`cmd.exe` with `rmdir /s /q` in command line:** Security EID 4688 and Sysmon EID 1 both capture the full command line. The `/s /q` flags specifically enable recursive silent deletion — a pattern rarely used by interactive users who would instead use Explorer or receive a confirmation prompt. Process command-line monitoring for `rmdir /s` or `rd /s` outside of known maintenance contexts is a reasonable detection approach.

**PowerShell parent spawning `cmd.exe` for deletion:** The process tree — `powershell.exe` → `cmd.exe` with `rmdir` — represents a common attacker pattern of using PowerShell as an orchestrator while delegating specific operations to `cmd.exe`. This lineage is visible in Sysmon EID 1 via the `ParentImage` and `ParentCommandLine` fields.

**Deletion targeting `%TEMP%` or staging directories:** The target path `%temp%\deleteme_T1551.004` is an obvious synthetic example, but the pattern of deleting a subdirectory within `%TEMP%` (especially one not matching standard Windows temp file naming) is characteristic of attacker staging directory cleanup. Monitoring for `rmdir` targeting unusual `%TEMP%` subdirectory names provides a useful behavioral signal.

**Absence of prior directory creation events:** If you have baseline visibility of which directories exist in `%TEMP%`, the sudden `rmdir` of a directory that was not observed being created (because creation happened before monitoring coverage) is an anomaly worth investigating.
