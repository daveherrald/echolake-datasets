# T1218.001-4: Compiled HTML File — Invoke CHM with InfoTech Storage Protocol Handler

## Technique Context

T1218.001 covers compiled HTML file abuse through `hh.exe`. Test 4 uses the `Invoke-ATHCompiledHelp` ATH function with the `-InfoTechStorageHandler its` parameter, which specifies the InfoTech Storage (ITS) protocol handler when opening the CHM file. The ITS protocol (`its://` or `its:`) is a Windows-specific URL protocol for accessing content within InfoTech compound document storage files, including CHM archives.

Using the `its:` protocol handler when opening CHM files is a technique variation that leverages URL-based CHM access rather than direct file path invocation. The InfoTech Storage protocol is processed by `itss.dll` (InfoTech Storage System DLL), and content accessed via the `its:` handler can bypass some security controls that filter direct file path access to CHM files. This variation produces a different invocation pattern and process chain compared to direct `hh.exe <path>` calls.

Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans approximately 4 seconds (2026-03-17T16:48:45Z–16:48:49Z) and contains 135 total events across three channels: 106 PowerShell events (105 EID 4104, 1 EID 4103), 3 Security events (all EID 4688), and 26 Sysmon events (17 EID 7, 3 EID 10, 3 EID 1, 2 EID 17, 1 EID 11).

The defining Sysmon EID 1 event captures the ATH PowerShell invocation: `"powershell.exe" & {Invoke-ATHCompiledHelp -InfoTechStorageHandler its -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` (tagged T1083, File and Directory Discovery). The `-InfoTechStorageHandler its` parameter distinguishes this test from T1218.001-3 and is the specific technique variation indicator. The parent process is the test framework SYSTEM PowerShell.

The remaining Sysmon EID 1 events are two `whoami.exe` invocations (T1033) — the pre- and post-test framework identity checks.

The ATH cleanup command `Invoke-AtomicTest T1218.001 -TestNumbers 4 -Cleanup -Confirm:$false` is visible in the PowerShell EID 4103 record.

Three Sysmon EID 10 process access events (all tagged T1055.001, full access 0x1FFFFF) record the test framework monitoring child processes.

The event structure here is nearly identical to T1218.001-3 in terms of counts and types (both show 26 Sysmon events, 106 PowerShell events, 3 Security events). The sole distinguishing difference is the `-InfoTechStorageHandler its` parameter in the PowerShell command line.

Compared to the defended dataset (sysmon: 36, security: 10, powershell: 45), the undefended run shows fewer Sysmon events (26 vs. 36) and fewer PowerShell events (106 vs. 45 — again the defended run shows more PowerShell events, suggesting Defender's interference generates additional PS activity). Security counts are similar (3 vs. 10).

## What This Dataset Does Not Contain

As with T1218.001-3, a Sysmon EID 1 event for `hh.exe` itself is absent. The ATH framework's in-process mechanism opens the CHM content using the ITS protocol handler without necessarily spawning hh.exe as an explicit child process creation visible to Sysmon's EID 1 monitoring.

`itss.dll` loading (the InfoTech Storage System DLL that handles the `its:` protocol) is not explicitly identified in the 17 EID 7 (image loaded) sample events, though it would be present in the full EID 7 stream as a DLL loaded by the `hh.exe` or hosting process.

No network, registry, file creation (beyond the PS profile), or DNS events are present.

## Assessment

Tests T1218.001-3 and T1218.001-4 produce nearly identical event footprints (same counts, same EID distribution, 4-second windows), with the only distinguishing observable being the PowerShell command line parameter `-InfoTechStorageHandler its`. This illustrates an important characteristic of ATH-based testing: the technique variation is encoded in the command-line arguments of the PowerShell invocation rather than in fundamentally different process chains or OS behaviors.

For detection purposes, the InfoTech Storage handler variation is meaningful because it represents a different underlying Windows API path than direct file invocation. The `its:` protocol triggers itss.dll loading and accesses the CHM content through the URL moniker infrastructure rather than direct file I/O. A real attacker might favor this approach precisely because it looks different from a simple file path argument and may bypass file-path-based detection rules.

The near-identical event structure across tests 3, 4, and 5 (same EID counts and distributions) demonstrates that the ATH framework's `Invoke-ATHCompiledHelp` function has a consistent execution footprint regardless of the specific CHM access mode. Detection approaches targeting the PowerShell command line parameters are more discriminating than approaches based on event counts or channel distributions alone.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — Invoke-ATHCompiledHelp with -InfoTechStorageHandler parameter:** The `-InfoTechStorageHandler its` parameter in the PowerShell command line identifies the specific technique variation. In real-world attacks, this would manifest as `hh.exe` being invoked with an `its:` protocol URL or as COM automation code constructing an ITS URL — neither of which would use the ATH function name.

**its: protocol handler invocations from non-browser contexts:** The InfoTech Storage protocol (`its://` or `ms-its:`) is intended for internal Windows help system use. Applications or processes constructing `its:` URLs to access CHM content outside of normal help system contexts should be treated as suspicious, particularly when the CHM file path embedded in the URL points to a user-writable or temp directory.

**itss.dll loaded by unexpected processes:** In the full Sysmon EID 7 stream (not in the current sample), loading of `itss.dll` into a process that is not `hh.exe` or a standard help viewer indicates that a CHM file is being accessed through COM automation or the URL moniker infrastructure rather than through the normal help viewer. This DLL load pattern combined with suspicious parent processes is a detection opportunity.

**Identical twin detection with T1218.001-3:** The near-identical event footprint of tests 3 and 4 illustrates that `Invoke-ATHCompiledHelp` variants are detectable as a class by the PowerShell command line pattern `Invoke-ATHCompiledHelp -.*HHFilePath.*hh\.exe.*CHMFilePath`, regardless of which access mode is specified. A single detection that matches this function invocation pattern would cover multiple ATH-based CHM technique variations.
