# T1218.001-3: Compiled HTML File — Invoke CHM with Default Shortcut Command Execution

## Technique Context

T1218.001 covers abuse of `hh.exe` and compiled HTML help files. Test 3 uses the Atomic Test Test framework (ATH) `Invoke-ATHCompiledHelp` PowerShell function to invoke a CHM file with default shortcut command execution. This approach uses PowerShell to orchestrate the CHM execution rather than invoking hh.exe directly from a command line, using the ATH framework's in-process mechanism to simulate the "default shortcut" execution path of a CHM file.

The `-HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm` parameters specify the HTML Help binary and a CHM file to open. The "default shortcut" context means the CHM is opened as if the user double-clicked it in Windows Explorer — using the file's associated handler rather than an explicit command-line invocation. This execution path produces a different process chain than a direct `cmd.exe /c hh.exe` invocation.

Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans approximately 4 seconds (2026-03-17T16:48:33Z–16:48:37Z) and contains 135 total events across three channels: 106 PowerShell events (105 EID 4104, 1 EID 4103), 3 Security events (all EID 4688), and 26 Sysmon events (17 EID 7, 3 EID 1, 3 EID 10, 2 EID 17, 1 EID 11).

The most distinctive Sysmon EID 1 event captures the ATH PowerShell invocation: `"powershell.exe" & {Invoke-ATHCompiledHelp -HHFilePath $env:windir\hh.exe -CHMFilePath Test.chm}` (tagged T1083, File and Directory Discovery — the rule fires because of the `Test-Path` calls within the ATH function). The parent is the test framework SYSTEM PowerShell process. This command line exposes the ATH function name and parameters, providing clear technique identification.

Two `whoami.exe` EID 1 events (tagged T1033) bookend the execution as the standard test framework pre- and post-test identity checks.

The ATH cleanup command `Invoke-AtomicTest T1218.001 -TestNumbers 3 -Cleanup -Confirm:$false` is visible in the PowerShell EID 4103 record.

Three Sysmon EID 10 process access events capture full-access handle opens (0x1FFFFF) from the test framework PowerShell to child processes — the standard ART test framework monitoring pattern tagged T1055.001 (DLL Injection).

Two Sysmon EID 17 named pipe events capture PSHost pipes for the test framework and child PowerShell sessions.

Compared to the defended dataset (sysmon: 37, security: 10, powershell: 45), the undefended run has slightly fewer Sysmon events (26 vs. 37) and fewer PowerShell events (106 vs. 45 — notably the defended run shows more PowerShell events here, which is atypical). The Security channel is similar (3 vs. 10). The lower undefended Sysmon count again reflects the absence of Defender scanning processes.

## What This Dataset Does Not Contain

A Sysmon EID 1 process creation event for `hh.exe` itself is absent. The ATH function's in-process invocation mechanism does not necessarily spawn hh.exe as a visible child process in the same way that a direct `cmd.exe /c hh.exe` call does. The "default shortcut" execution path may use COM interfaces or API calls to open the CHM file rather than spawning hh.exe as a new child process.

No network events, registry events, or DNS query events are present. The CHM file `Test.chm` used in this test appears to be a local file, and the test does not generate network activity.

The actual execution of the CHM's embedded script content is not visible in the PowerShell log.

## Assessment

This dataset demonstrates a significant contrast with T1218.001-1 (local payload, direct invocation): using the ATH framework's `Invoke-ATHCompiledHelp` function produces a different event signature. The PowerShell command line containing `Invoke-ATHCompiledHelp` is the most direct technique identification signal, but it exposes the ATH test framework rather than what a real-world attacker would use.

In a real attack scenario using the "default shortcut" execution path, the adversary would likely use COM automation, WScript.Shell, or similar mechanisms to open the CHM file through the Windows shell's file association handler. The resulting process chain would differ from both the direct `hh.exe` invocation (test 1/2) and the ATH-driven invocation visible here.

The 4-second execution window and 26 Sysmon events make this one of the smaller datasets in the T1218.001 series, reflecting the ATH function's streamlined execution approach compared to the 2-minute test 1/2 captures.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — Invoke-ATHCompiledHelp in PowerShell command line:** The `Invoke-ATHCompiledHelp` function name is specific to the ATH test framework and would not appear in real-world attacks. However, PowerShell commands that reference `hh.exe` or CHM file paths in script block arguments are detection-relevant regardless of the specific invocation framework.

**PowerShell (SYSTEM) spawning a PowerShell child with CHM-related arguments:** A SYSTEM-context PowerShell process spawning a child PowerShell process that references `hh.exe` is unusual and warrants investigation. The parent-child PowerShell relationship combined with CHM-related arguments distinguishes this from legitimate help system access.

**Sysmon EID 10 — full process access from PowerShell (SYSTEM) to child processes:** As in other ATH-driven tests, the test framework's full-access (0x1FFFFF) handle opens to child processes are a consistent artifact of ATH-based technique execution. In a real attack, similar process access patterns would appear if the adversary used PowerShell-based automation to manage payload execution.

**CHM file at a non-standard path:** The `Test.chm` filename and its implicit path within a SYSTEM PowerShell's working directory is not a path where legitimate CHM files are stored. Windows ships help content to `%SystemRoot%\Help\` and applications install their help files in vendor-specific program directories.
