# T1070.004-10: File Deletion — Delete TeamViewer Log Files

## Technique Context

Remote access tools like TeamViewer maintain detailed logs of their sessions: connection timestamps, remote IP addresses, accessed files, chat messages, and user account activity. When attackers use TeamViewer (or similar remote tools) for initial access or lateral movement, these logs become incriminating evidence. Deleting them is a targeted anti-forensic step specific to the tool used for access.

T1070.004-10 simulates this cleanup by creating a synthetic TeamViewer log file (`TeamViewer_54.log` in `%TEMP%`) and then deleting it with `Remove-Item`. The naming convention mirrors actual TeamViewer log files, which are named with session-based numeric suffixes (e.g., `TeamViewer_15.log`). In a real attack scenario, the files targeted would be in TeamViewer's actual log directory (typically `C:\Program Files (x86)\TeamViewer\` or `C:\Users\<user>\AppData\Roaming\TeamViewer\`) rather than `%TEMP%`.

This test is notable because it combines two operations: file creation (to have something to delete) and file deletion (the technique itself). Both operations are logged, giving analysts visibility into the test artifact's full lifecycle.

Windows Defender does not detect or block this technique. The undefended and defended variants produce essentially identical behavior.

## What This Dataset Contains

Security EID 4688 captures the PowerShell process launch with command line: `"powershell.exe" & {New-Item -Path $env:TEMP\TeamViewer_54.log -Force | Out-Null Remove-Item $env:TEMP\TeamViewer_54.log -Force -ErrorAction Ignore}`. This single command creates and then immediately deletes the simulated log file. Both operations are in the same PowerShell block, so they appear as a single process creation event rather than two separate operations.

Sysmon EID 1 captures the same process launch with identical command line, tagged `technique_id=T1059.001,technique_name=PowerShell`, with parent `powershell.exe` (the ART orchestration process).

Sysmon EID 11 records two file creation events during this test window. One corresponds to the `New-Item` command creating `TeamViewer_54.log` in `%TEMP%`. The other is the PowerShell startup profile cache write at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`. The `New-Item` file creation is logged by Sysmon EID 11; the subsequent `Remove-Item` deletion is not captured by Sysmon EID 23/26 in this configuration.

PowerShell script block logging (EID 4104) captures 97 events. The ART cleanup script block is present: `try { Invoke-AtomicTest T1070.004 -TestNumbers 10 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`. The main technique payload appears in the Sysmon EID 1 command line.

The dataset contains 135 total events: 97 PowerShell, 4 Security, and 34 Sysmon.

## What This Dataset Does Not Contain

The file deletion operation itself is not directly captured as a separate event. While Sysmon EID 11 records the file creation (`New-Item`), there is no corresponding Sysmon EID 23 or EID 26 for the `Remove-Item` deletion. File object access auditing (Security EID 4663) was not enabled, so there are no handle-based access records for the file operations.

The dataset does not represent a realistic attack scenario path for this technique. The test file was created in `%TEMP%` rather than in an actual TeamViewer log directory, so the file path does not match what a real TeamViewer cleanup would look like. In a real incident, the deleted files would be under TeamViewer's own application directories.

No TeamViewer process events, installation registry keys, or TeamViewer-specific log content are present. This is purely a file creation and deletion simulation.

No network artifacts, Defender events, or registry modifications are present.

## Assessment

This dataset captures the enclosing PowerShell command with full fidelity, but the actual file deletion operation leaves no direct telemetry. The command line makes the intent clear (`Remove-Item $env:TEMP\TeamViewer_54.log`), and Sysmon EID 11 records the creation of the file that was then deleted — so an analyst can observe the full lifecycle through inference, even without a dedicated deletion event.

Compared to the defended variant (27 Sysmon, 10 Security, 31 PowerShell), the undefended run has more events overall (34 Sysmon, 4 Security, 97 PowerShell), with the PowerShell difference again reflecting the ART test framework variation seen across this series. The technique execution profile is substantively identical between the two variants.

The dataset's value for training detectors lies in the combination of `New-Item` followed immediately by `Remove-Item` in a single PowerShell block targeting a path that includes a log filename pattern associated with remote access tools.

## Detection Opportunities Present in This Data

**PowerShell command line creating then deleting a `*TeamViewer*.log` file:** Both Security EID 4688 and Sysmon EID 1 capture the exact command. The pattern of creating and immediately deleting a file named `TeamViewer_NN.log` is not a pattern any legitimate TeamViewer installation would produce — actual TeamViewer creates these files during sessions, not via PowerShell. This specific combination (create + delete in a PowerShell one-liner with a TeamViewer log filename) is highly suspicious.

**`Remove-Item` targeting remote access tool log patterns:** Monitoring for PowerShell invocations with `Remove-Item` (or equivalent) targeting files matching patterns like `TeamViewer_*.log`, `Radmin*.log`, `AnyDesk*.log`, or similar remote tool log naming conventions is a productive detection strategy, especially when the processes are running as SYSTEM or from unexpected parent processes.

**Sysmon EID 11 file creation for known log file patterns:** If `TeamViewer_54.log` were created in an actual TeamViewer directory (not `%TEMP%`), Sysmon EID 11 would record that creation. The absence of a subsequent EID 23 while a PowerShell process with `Remove-Item` in its command line ran can be correlated to identify the deletion despite the lack of a direct deletion event.

**PowerShell spawned as SYSTEM deleting log files:** The execution context (`NT AUTHORITY\SYSTEM`, `SubjectUserName: ACME-WS06$`) combined with a file deletion targeting application log files is an anomaly in environments where TeamViewer or similar tools are used, since those tools normally manage their own logs under the user context that ran the session.
