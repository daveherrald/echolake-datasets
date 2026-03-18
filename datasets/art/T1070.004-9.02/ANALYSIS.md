# T1070.004-9: File Deletion — Delete Prefetch File

## Technique Context

Windows Prefetch files (`.pf` files in `C:\Windows\Prefetch\`) are forensic gold. Each prefetch file records when an executable last ran, how many times it has run, the DLLs and files it accessed, and its filesystem paths — all encoded in the filename itself (e.g., `POWERSHELL.EXE-XXXXXXXX.pf`). Forensic analysts routinely parse prefetch files to reconstruct program execution history, especially for tools that have since been deleted from disk.

Deleting prefetch files is therefore a targeted anti-forensic action: it removes execution history for the programs whose prefetch files are deleted. T1070.004-9 demonstrates this by using PowerShell's `Remove-Item` cmdlet to delete the first prefetch file found in `C:\Windows\Prefetch\`. In a real attack, an adversary would target specific prefetch files — those for their tools, for `cmd.exe` used in a specific attack window, or for credential dumping utilities — to erase evidence of execution.

The technique requires access to `C:\Windows\Prefetch\`, which is typically restricted to administrators and `NT AUTHORITY\SYSTEM`. The test runs as SYSTEM via the QEMU guest agent execution path.

Both the defended and undefended variants completed successfully. Windows Defender does not block deletion of prefetch files.

## What This Dataset Contains

The central technique evidence is Security EID 4688 recording the PowerShell launch with command line: `"powershell.exe" & {Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])}`. This command enumerates all `.pf` files in `C:\Windows\Prefetch\`, takes the first one (`[0]`), and deletes it. The full path is constructed dynamically using `$Env:SystemRoot`, but at execution time resolves to `C:\Windows\Prefetch\<filename>.pf`.

Sysmon EID 1 captures the same PowerShell process launch with the same command line, tagging it with `technique_id=T1059.001,technique_name=PowerShell`. The parent is the ART orchestration `powershell.exe` process.

A second Security EID 4688 and Sysmon EID 1 entry records an empty-body PowerShell invocation (`"powershell.exe" & {}`) — the ART cleanup command, which here is a no-op since the deleted file was the target artifact itself.

PowerShell script block logging (EID 4104) captures 100 events with 97 being EID 4104 and 3 being EID 4103 (pipeline execution detail). The ART module import is visible, and the cleanup block appears as a separate script block entry. The bulk of the 97 EID 4104 events are internal PowerShell runtime script blocks, not technique-specific content.

Sysmon EID 17 records named pipe creation events for the PowerShell host instances. Sysmon EID 10 records process access events (PowerShell accessing other processes with full access mask `0x1FFFFF`). Sysmon EID 11 records a file write to the PowerShell startup profile cache path.

The dataset contains 132 total events: 100 PowerShell, 4 Security, and 28 Sysmon.

## What This Dataset Does Not Contain

The dataset does not record which specific prefetch file was deleted. The command dynamically selects `[0]` from a `Get-ChildItem` enumeration of `C:\Windows\Prefetch\*.pf`, but neither the Security log nor Sysmon (in this configuration) captures the resolved filename of the deleted file. You know a prefetch file was deleted; you do not know which one.

There are no Sysmon EID 23 (file deleted) or EID 26 (file delete detected/archived) events. Sysmon's file deletion monitoring was not configured to watch `C:\Windows\Prefetch\`.

There are no file access audit events (Security EID 4663) for the `C:\Windows\Prefetch\` directory enumeration or the specific file deletion. Object access auditing was not enabled.

The dataset does not contain the prefetch data itself — the content of the deleted `.pf` file is not preserved. A forensic analyst working with this dataset cannot determine what executable's execution history was erased.

No network artifacts, registry changes, or Defender events are present.

## Assessment

This dataset provides reliable evidence that a prefetch file was deleted via PowerShell, but does not identify which file was targeted. The command line evidence is strong: `Remove-Item` combined with `Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf"` and `[0]` indexing unambiguously describes the targeting logic even without knowing the resolved filename.

Compared to the defended variant (26 Sysmon, 10 Security, 28 PowerShell), the undefended run has substantially more PowerShell script block events (100 vs. 28) but a comparable Security and Sysmon event profile. This PowerShell disparity is consistent with the broader pattern observed across this undefended dataset series, where ART test framework execution in the undefended environment generates more verbose script block logging.

The technique is fully executed in this dataset. The prefetch file was deleted — this is not a partial or blocked execution. The dataset's forensic limitation is the absence of file-level deletion telemetry rather than any issue with technique execution quality.

## Detection Opportunities Present in This Data

**PowerShell command line targeting `Prefetch\*.pf` with `Remove-Item`:** Security EID 4688 and Sysmon EID 1 both capture the complete command line. The combination of `Get-ChildItem` enumerating `.pf` files followed by `Remove-Item` is a precise behavioral indicator. Legitimate prefetch file management is rare and typically performed by system utilities, not ad-hoc PowerShell one-liners.

**Access to `C:\Windows\Prefetch\` from PowerShell:** If file access auditing were enabled on the Prefetch directory, Security EID 4663 events would show the enumeration and deletion. Even without auditing, monitoring for PowerShell processes with command lines referencing `$Env:SystemRoot\prefetch` or `C:\Windows\prefetch` is a useful detection heuristic.

**Sysmon EID 10 process access from PowerShell:** The process access events showing PowerShell opening other processes are background noise in this dataset, but a Sysmon configuration with EID 23/26 (file delete monitoring) covering `C:\Windows\Prefetch\` would produce a direct artifact of the deletion. This dataset demonstrates the detection gap that exists without such configuration.

**Timing correlation with execution gaps in other telemetry:** If an analyst is examining this system's other event logs and notices gaps in expected program execution history, the absence of prefetch entries combined with a PowerShell process targeting the Prefetch directory in the logs is a strong combined indicator.
