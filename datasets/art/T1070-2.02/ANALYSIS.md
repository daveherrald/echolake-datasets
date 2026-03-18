# T1070-2: Indicator Removal — Indicator Manipulation using FSUtil

## Technique Context

T1070 Indicator Removal covers the broad category of techniques adversaries use to destroy or modify artifacts that would reveal their presence on a system. This specific test demonstrates `fsutil.exe` being used to overwrite the contents of a file with null bytes via the `setZeroData` subcommand. Unlike simply deleting a file, zeroing data in place preserves the file's existence, size, and timestamps while destroying its content — a subtler form of evidence tampering that can fool tools relying on file presence or metadata rather than content hashing.

`fsutil.exe` is a legitimate Windows built-in administrative utility. Its presence in a process tree is not inherently suspicious, which makes it attractive for attackers. The `setZeroData` subcommand, however, has a narrow legitimate use: it is primarily used by storage optimization software to prepare files for sparse storage. Seeing it invoked from a PowerShell parent against an arbitrary file path is a strong behavioral indicator.

In the defended variant of this dataset, Windows Defender was active but did not block the technique — FSUtil is not traditionally flagged by AV. The undefended variant provides the same technique execution in a fully uninhibited environment.

## What This Dataset Contains

The dataset captures the full execution chain for a file content zeroing operation. Security EID 4688 records the direct FSUtil invocation: `"C:\Windows\system32\fsutil.exe" file setZeroData offset=0 length=10 C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1070-2.txt`. This shows the exact parameters — offset 0, length 10 — targeting the payload file.

Sysmon EID 1 records the same process creation with richer context. The parent process is `powershell.exe` (PID 17052), and the parent command line reveals the full three-step attack sequence: create the file, write content (`echo "1234567890"`), then zero it with FSUtil. The Sysmon rule tag `technique_id=T1070,technique_name=Indicator Removal` confirms the action was matched by the deployed Sysmon configuration.

A second Sysmon EID 1 records the enclosing PowerShell process itself, with command line: `"powershell.exe" & {if (-not (Test-Path "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1070-2.txt")) { New-Item ... -Force } echo "1234567890" > "...T1070-2.txt" fsutil file setZeroData offset=0 length=10 "...T1070-2.txt"}`. This is the complete ART test payload, logged via EID 4688 as well with the rule tag `technique_id=T1059.001,technique_name=PowerShell`.

PowerShell script block logging (EID 4104) captures 95 events across the test framework lifecycle, including the ART module import (`Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force`) and supporting infrastructure calls. The technique payload itself is visible in the Sysmon parent command line rather than as a standalone EID 4104 entry, because it was passed as a direct `& {...}` block rather than a named script file.

Sysmon EID 7 (image loaded) records 22 DLL loads into the PowerShell process, including `mscoree.dll` and `mscoreei.dll` (tagged `technique_id=T1055,technique_name=Process Injection` by Sysmon rules — this is a false-positive rule tag on normal .NET initialization, not actual injection). Sysmon EID 10 (process access) records PowerShell opening handles to `whoami.exe` and `fsutil.exe` with full access mask `0x1FFFFF`. Sysmon EID 17 records named pipe creation for PowerShell host communication. Sysmon EID 11 records a file write to the PowerShell startup profile cache at `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`.

The dataset spans approximately 4 seconds (23:24:31 to 23:24:35 UTC on 2026-03-14) and contains 136 total events: 95 PowerShell, 5 Security, and 36 Sysmon.

## What This Dataset Does Not Contain

File content auditing is absent. Windows object access auditing was not enabled for this host, so there are no Security EID 4663 (object access) or EID 4658 (handle close) events showing the actual read or write operations against `T1070-2.txt`. You can see that the command ran, but not the low-level file handle activity.

There are no Sysmon EID 23 (file delete) or EID 26 (file delete detected) events, as those cover file deletion rather than in-place content modification. The file was not deleted — it was zeroed.

The dataset does not include network events. This technique is entirely local and generates no DNS, TCP, or named pipe network activity.

No Defender telemetry, WMI subscription events, or scheduled task artifacts are present. The cleanup phase (`powershell.exe & {}` recorded in Security EID 4688) represents the ART cleanup command, which in this case was a no-op since the zeroed file was the artifact itself.

## Assessment

This is a high-fidelity, fully executed technique capture. The core FSUtil invocation is present in both Security EID 4688 and Sysmon EID 1 with complete command lines, and the parent PowerShell process chain is fully reconstructed. The undefended execution produced the same event profile as the defended variant because Defender does not detect or block FSUtil `setZeroData` usage — the technique completed successfully in both environments.

The event count difference between this dataset (136 total) and the defended variant (77 total: 28 Sysmon, 12 Security, 37 PowerShell) reflects additional PowerShell script block recording from the undefended environment's slightly different ART test framework execution path, not a meaningful behavioral difference.

The primary limitation is the absence of file access auditing, which would provide direct evidence that the file content was modified at the OS level. The technique execution evidence is nonetheless unambiguous: the command line is captured, the process lineage is clear, and the target file path is explicitly recorded.

## Detection Opportunities Present in This Data

**FSUtil `setZeroData` invocation (high fidelity):** Security EID 4688 and Sysmon EID 1 both record the complete command line `fsutil.exe file setZeroData offset=0 length=10 <path>`. The `setZeroData` argument has no common legitimate use outside storage tooling and makes a reliable detection anchor. Any non-storage-related parent process spawning `fsutil.exe` with this subcommand warrants investigation.

**PowerShell parent spawning FSUtil:** The process tree — `powershell.exe` (parent) → `fsutil.exe` (child) with `setZeroData` — is a strong behavioral pattern. Sysmon EID 1 captures both the parent command line (the full payload script) and the child invocation, enabling parent-child correlation.

**Script block containing FSUtil invocation:** The parent PowerShell process's command line (visible in Sysmon EID 1 and Security EID 4688 for the spawned PowerShell) contains `fsutil file setZeroData` as a string, detectable via command-line content inspection regardless of obfuscation of the PowerShell wrapper.

**Sysmon EID 10 process access from PowerShell to fsutil.exe:** PowerShell opening a full-access handle (`0x1FFFFF`) to `fsutil.exe` is recorded in Sysmon EID 10. While this alone is not a detection, it corroborates the process launch and can serve as a supporting signal in a multi-event correlation.
