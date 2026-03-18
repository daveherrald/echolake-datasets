# T1559.002-2: Dynamic Data Exchange — Execute PowerShell Script via Word DDE

## Technique Context

T1559.002 covers Dynamic Data Exchange (DDE) as an execution mechanism. DDE is a legacy Windows IPC protocol originally designed for inter-application data sharing. Adversaries abuse DDE fields embedded in Microsoft Office documents to execute arbitrary commands when the document is opened — without requiring macros. The technique gained wide attention after 2017 and was exploited in phishing campaigns delivering shellcode and backdoors. Microsoft later added warnings and disabled automatic DDE execution in Office by default.

Test 2 specifically abuses a pre-built Word document containing a DDE field that launches a PowerShell script. The ART test framework opens the document file, expecting Word to process the embedded DDE payload and spawn PowerShell.

## What This Dataset Contains

The dataset covers a 2-second window (2026-03-15 00:13:50–00:13:52 UTC) and contains 110 PowerShell events and 11 Sysmon events across two log sources — notably absent are Security (4688) process creation events, WMI events, and System events that appeared in the defended variant.

The Sysmon events are entirely composed of EID 7 (ImageLoad) events against `powershell.exe` (PID 3676 running as `NT AUTHORITY\SYSTEM`), recording the standard .NET and PowerShell DLL load sequence:
- `mscoree.dll` — .NET Runtime Execution Engine (tagged T1055)
- `mscoreei.dll` — .NET Runtime Execution Engine
- `clr.dll` — .NET Common Language Runtime
- `mscorlib.ni.dll` — .NET Framework class library (native image)
- `System.Management.Automation.ni.dll` — PowerShell automation assembly (tagged T1059.001)
- `MpOAV.dll` and `MpClient.dll` — Windows Defender DLLs (tagged T1574.002 DLL Side-Loading)
- `urlmon.dll` — OLE32 Extensions, part of the PowerShell initialization sequence
- `clrjit.dll` — .NET JIT compiler

Sysmon EID 17 records the creation of the named pipe `\PSHost.134180072299729825.3676.DefaultAppDomain.powershell` by `powershell.exe` — the standard PowerShell host communication pipe created at startup.

Sysmon EID 11 records a file creation by `powershell.exe`:
```
C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive
```
This is the PowerShell interactive session profile data file, written when a new PowerShell session initializes.

The 110 PowerShell events consist of 107 EID 4104 script block logging events and 3 EID 4103 module logging events. The 4104 events contain only ART test framework error-handling boilerplate scriptblocks (`{ Set-StrictMode -Version 1; $_.PSMessageDetails }`, `{ Set-StrictMode -Version 1; $_.ErrorCategory_Message }`, etc.). The 4103 events record a single `Write-Host` invocation with the value `"DONE"` — confirming the ART test framework completed its execution wrapper.

Critically, no DDE payload content, no Word process, and no `powershell.exe` child process spawned from Word appear in the telemetry.

## What This Dataset Does Not Contain

No Word (WINWORD.EXE) process creation is visible. The ART test framework invokes `cmd.exe /c start DDE_Document.docx` in the defended variant, and Word spawns as a child. In the undefended variant, no `cmd.exe` or `WINWORD.EXE` process appears in Security 4688 or Sysmon EID 1 — indicating that the test execution mechanism changed, or that the Word-DDE execution path did not trigger in this run.

No DDE payload script block appears in PowerShell EID 4104. The purpose of DDE execution is to spawn a PowerShell command from within the DDE field itself. If Word had launched PowerShell via DDE, that PowerShell process would have generated its own 4104 events with the DDE payload content. The absence of payload script blocks confirms the DDE execution path was not completed.

No process chain (powershell.exe → cmd.exe → WINWORD.EXE → cmd.exe) appears in any log source. In the defended dataset, Security 4688 and Sysmon EID 1 documented this chain explicitly. Here, only the ART test framework PowerShell process appears in the telemetry.

No Security 4688 events are present at all. This is the most significant structural difference from the defended variant (which had 21 Security events). The absence suggests either the Security channel was not collected, or the test framework ran entirely within the existing SYSTEM PowerShell process without spawning new processes.

## Assessment

This dataset occupies an unusual position: the telemetry reflects the ART test framework PowerShell process initialization rather than the DDE execution technique itself. The 110 PowerShell events and 11 Sysmon events are consistent with what you see from any PowerShell process startup — DLL loads, pipe creation, profile data file writes, and error-handler scriptblocks. No Word DDE chain is visible.

Compared to the defended variant, the undefended run produced a dramatically smaller dataset (121 total events versus 84 events across five log sources in the defended run). The defended variant had the richer telemetry because Defender's process scanning triggered additional WMI, Security logon, and System events as it responded to the Word process launch. The undefended run shows only the test framework layer.

The primary research value of this dataset is negative evidence: it establishes what the baseline PowerShell startup telemetry looks like in the SYSTEM context on this host, independent of any DDE exploitation. If you are building detection logic, the defended variant of this test provides substantially more useful signal.

## Detection Opportunities Present in This Data

Despite the incomplete execution, several detection-relevant observations apply:

**Sysmon EID 7 for `MpOAV.dll` and `MpClient.dll`** loaded into `powershell.exe` and tagged with `RuleName: technique_id=T1574.002,technique_name=DLL Side-Loading` by sysmon-modular. The Defender DLL loading into a PowerShell process is a routine behavior that does not indicate malice here, but the tagging illustrates how sysmon-modular rules can produce false positives on system DLL loads.

**Sysmon EID 17** `\PSHost.*` named pipe creation by `powershell.exe` running as SYSTEM. PowerShell creating this pipe is normal, but PowerShell running as SYSTEM in the context of a DDE exploitation scenario is not — the pipe's existence can be correlated with the process context to evaluate legitimacy.

**PowerShell EID 4103 `Write-Host "DONE"`**: This specific module logging event appears at the end of every ART test framework execution, confirming the test framework completed. In a real attacker context, seeing `Write-Host "DONE"` from SYSTEM PowerShell after a series of DLL loads would be unusual.

If the DDE execution had completed successfully, the detection opportunity would be a PowerShell process created as a child of `WINWORD.EXE` (Security EID 4688 showing parent `WINWORD.EXE`) — a high-confidence indicator with very few legitimate explanations on most endpoints.
