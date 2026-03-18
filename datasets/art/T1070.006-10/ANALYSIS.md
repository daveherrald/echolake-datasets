# T1070.006-10: Timestomp — Event Log Manipulations: Time Slipping via PowerShell

## Technique Context

T1070.006 (Timestomp) covers adversary manipulation of file or system timestamps to disrupt forensic analysis and evade timeline-based detections. This test implements a specific variant known as "time slipping": the system clock is advanced forward by several days using PowerShell's `Set-Date` cmdlet, activity occurs at the falsified time, and the clock is then restored to the correct time on cleanup. The technique directly corrupts the integrity of Windows Event Log timestamps, making it significantly harder for analysts to reconstruct accurate attack timelines. This approach has been documented in real intrusions where attackers slide the system clock to make malicious events appear to predate or postdate their actual occurrence. Unlike file-level timestomping (which targets individual NTFS MACE attributes), time slipping affects every event logged while the clock was displaced — potentially hundreds of thousands of records.

## What This Dataset Contains

This dataset spans roughly 3 days of wall-clock time (2026-03-13T18:48:26Z through 2026-03-16T18:48:32Z) across 50,918 Sysmon events and 17,025 Security events, making it the largest dataset in this collection by event count. The extended time window is a direct artifact of the technique: the test advances the system clock by 3 days using `Set-Date -Date (Get-Date).AddDays(3)` and writes the shift amount to `%APPDATA%\slipDays.bak`, then the cleanup command reads that file and restores the original time. Events logged between the forward-shift and the restore are timestamped approximately 3 days in the future relative to when execution actually occurred.

**Security EID 4616** (System time change) is the direct detection artifact for this technique. Seven events of this type are present, each recording the previous and new system time values as set by `powershell.exe` under SYSTEM context. A sample 4616 shows the previous time as `2026-03-16T18:48:43Z` and the new time as `2026-03-13T18:48:43Z` — the clock rolling back 3 days during cleanup. The before/after timestamps in 4616 reveal the exact magnitude of the slip.

**Security EID 4688** (Process creation) and **Sysmon EID 1** both capture the PowerShell processes executing the time-slip commands. The command lines are fully preserved: the setup command shows `Set-Date -Date (Get-Date).AddDays(3)` followed by `Add-Content "$env:APPDATA\slipDays.bak" 3`, and the cleanup command shows the restore loop reading `slipDays.bak` and calling `Set-Date -Date (Get-Date).AddDays(-$line)`. Both commands run under `NT AUTHORITY\SYSTEM` as child processes of the ART framework's parent PowerShell.

**Security EID 4703** (Token right adjusted) is present with 1,109 events, showing `SeSystemtimePrivilege` being enabled in PowerShell tokens. Changing the system clock requires `SeSystemtimePrivilege`; when this privilege is adjusted in the context of a PowerShell process, it is a precursor indicator for time manipulation.

**Sysmon EID 11** (File created) captures the creation of `C:\Windows\System32\config\systemprofile\AppData\Roaming\slipDays.bak` — the persistence file used to track the time slip amount and enable cleanup.

The dataset also contains substantial OS-background Sysmon telemetry accumulated over the 3-day slip window: EID 7 (30,888 image loads), EID 3 (200 network connections), EID 22 (2,658 DNS queries), EID 10 (3,092 process access events), EID 17 (3,432 pipe creation events), EID 12/13 (registry events), EID 19/20/21 (WMI events), EID 25 (process tampering), and EID 26 (file delete logged). These reflect normal Windows service activity timestamped during the slip window, not adversary actions.

## What This Dataset Does Not Contain

There are no PowerShell script block logs (EID 4103/4104) in this dataset. The collection window did not capture PowerShell channel events for this test run, so the full script text is only available via the command-line fields in Security 4688 and Sysmon EID 1.

There are no Sysmon EID 2 (File creation time changed) events. The technique targets the system clock rather than individual file MACE timestamps, so file-level timestamp modification events are not expected here.

No Security EID 4704 (user right assigned) events appear confirming the privilege grant that enabled `SeSystemtimePrivilege`. The privilege adjustment is visible only through 4703 (token right adjusted), not through an explicit assignment event.

The dataset does not capture whether the time slip caused any downstream artifacts in other applications or services that act on system time, such as certificate validity checks, Kerberos ticket expirations, or scheduled task misfires.

## Assessment

This is a high-value dataset for detecting time-based evasion techniques. The 4616 events provide ground truth for the exact moments when the system clock was manipulated and the precise time deltas involved. The 4703 events showing `SeSystemtimePrivilege` elevation provide a leading indicator detectable before the clock actually changes. The process creation records contain the full PowerShell command lines, making it straightforward to build behavioral detections on `Set-Date` combined with `AddDays` in a SYSTEM-context PowerShell process. The large volume of background events — nearly 68,000 total — also makes this dataset useful for testing detection precision: a good time-slip detection should fire on the handful of 4616 events without triggering on the tens of thousands of OS-noise events surrounding them.

The 3-day time span is unusual for an ART dataset and should be understood as an artifact of the technique rather than a data quality problem. Events at timestamps like `2026-03-15` and `2026-03-16` are real events that occurred on `2026-03-13` while the clock was slipped forward.

## Detection Opportunities Present in This Data

- **Security EID 4616**: System time change events with `powershell.exe` as the process name; the Windows Time Service is the only legitimate process that should generate 4616, making any other caller highly suspicious. The before/after time fields quantify the slip magnitude.

- **Security EID 4703 with SeSystemtimePrivilege**: Token right adjustments enabling `SeSystemtimePrivilege` in a PowerShell process running as SYSTEM; this fires before the clock actually changes and is a reliable leading indicator.

- **Security EID 4688 / Sysmon EID 1 command-line matching**: PowerShell spawning with command lines containing `Set-Date` combined with `AddDays` or `AddHours`; this pattern is specific to programmatic time manipulation and has no legitimate counterpart in normal operations.

- **Sysmon EID 11 for slipDays.bak**: File creation of `%APPDATA%\slipDays.bak` or any file matching a pattern used to persist time-slip state; this artifact is specific to this ART test's implementation but represents a category of state-tracking files used by cleanup-aware attack tools.

- **Timestamp gap analysis**: Events from a host appearing with timestamps 2–7 days in the future relative to other hosts in the same environment; cross-host timestamp correlation can expose time slips that individual host detections miss.

- **Process chain analysis**: SYSTEM-context PowerShell spawning a child PowerShell with an inline script block containing `Set-Date`; the two-hop PowerShell chain (ART framework parent → technique executor child) is visible in both Sysmon EID 1 and Security 4688.
