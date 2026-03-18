# T1055.012-3: Process Hollowing — Process Hollowing in Go using CreateProcessW WinAPI

## Technique Context

Process Hollowing (T1055.012) is a defense evasion and privilege escalation technique where an attacker creates a legitimate target process in a suspended state, replaces its memory contents with malicious code, and resumes execution. The attack sequence involves calling `CreateProcess` with the `CREATE_SUSPENDED` flag, unmapping the target image from memory using `NtUnmapViewOfSection`, allocating new executable memory via `VirtualAllocEx`, writing attacker-controlled code with `WriteProcessMemory`, updating the thread context to redirect execution, and finally calling `ResumeThread`. Because the final running process has the name and PID of a legitimate Windows binary, it evades process listing checks and can inherit the trust attributes of the target.

This specific test uses a Go-compiled binary (`CreateProcess.exe`) that targets `werfault.exe` — the Windows Error Reporting process. `WerFault.exe` is a common hollowing target because it runs as a child of many system processes, is present on all Windows installations, and is trusted by both users and security tooling. The Go implementation is notable because it avoids the .NET or PowerShell runtime typically associated with commodity offensive tooling and uses native Windows API calls directly.

Detection focuses on several behavioral signals: process access events (`PROCESS_ALL_ACCESS` / `0x1FFFFF`) against a newly-created process, memory allocation followed by write operations in a target process, thread context manipulation, and the combination of a suspicious parent spawning a legitimate child that then behaves unexpectedly. In this undefended version, the hollowing binary runs to completion — producing artifacts that are absent when Defender terminates the tooling before it can act.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:16:38Z to 23:16:43Z) and records 145 events across four channels: Sysmon (35), PowerShell (105), Security (4), and Application (1).

**The launch chain is visible in Security EID 4688 and Sysmon EID 1.** The ART test framework spawns a child PowerShell with the full command line:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcess.exe -program "C:\Windows\System32\werfault.exe" -debug}
```

This command line is the primary forensic anchor for this test — it names the hollowing binary explicitly, the target binary (`werfault.exe`), and a `-debug` flag that suggests the Go implementation captures output or waits for confirmation.

**Sysmon EID 10 (ProcessAccess)** records cross-process memory access with `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS). Two targets appear in the samples: `whoami.exe` (the test framework's own discovery step) and a second PowerShell process. The call trace is consistent across both: `ntdll.dll → KERNELBASE.dll → .NET/CLR assembly code`, reflecting that the PowerShell test framework process itself is making the OpenProcess calls via managed code. In the undefended run these accesses complete successfully — in the defended version (45 sysmon events vs. 35 here), additional EID 10 events from Defender's own scanning are present, inflating totals.

**Sysmon EID 7 (ImageLoad)** contributes 23 events showing .NET runtime DLL loads into the test framework PowerShell process: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`. Also present are Windows Defender DLL loads (`MpOAV.dll`, `MpClient.dll`) — Defender is present but inactive in this dataset due to the disabled state. The URL-handling library `urlmon.dll` loads into the test framework process as well, consistent with the ART framework's network check behavior.

**Sysmon EID 17 (PipeCreate)** shows the test framework PowerShell creating a named pipe: `\PSHost.134180037964426843.6728.DefaultAppDomain.powershell`. This is the standard PowerShell host communication pipe — unremarkable on its own but useful for correlating the specific PowerShell instance across events.

**Sysmon EID 11 (FileCreate)** records one file creation event.

**PowerShell EID 4104 (ScriptBlock)** contributes 105 events, the majority of which are framework boilerplate (`Set-StrictMode`, error-handling closures, `$ErrorActionPreference`). These represent the ART test framework infrastructure. The dataset does not include a sample containing the actual hollowing invocation in `ScriptBlockText`, though the full script block is present in the raw event data.

Compared to the defended version (which recorded 45 sysmon, 10 security, 46 PowerShell events), the undefended dataset shows slightly fewer Sysmon events (35) but 4 Security 4688 events vs. 10 in the defended run. This likely reflects that Defender's own process creation activity during blocking inflated the defended totals — without Defender acting, only the actual attack process chain is recorded.

## What This Dataset Does Not Contain

No Sysmon EID 1 event for `werfault.exe` itself appears in the samples, which is notable. The Go hollowing binary is expected to create `werfault.exe` in a suspended state before injecting — the absence could indicate that the sysmon-modular include-mode filter did not match `werfault.exe`, or that the injection target was not separately captured. The custom `CreateProcess.exe` binary similarly does not appear in EID 1 events, consistent with include-mode filtering that only captures known suspicious parent/child relationships.

No Sysmon EID 8 (CreateRemoteThread) or explicit memory-write events appear. These would be the strongest behavioral indicators of successful hollowing; their absence may reflect Sysmon configuration limitations (EID 8 requires specific configuration) or the Go implementation not triggering that particular hook.

The PowerShell EID 4104 samples are dominated by boilerplate. The actual script block containing the hollowing invocation is not represented in the provided samples, limiting scripted content review.

The Application channel contributes a single event (EID 15), which is a Windows Defender status update — a residual artifact of the disabled-but-installed state of Defender.

## Assessment

This dataset provides clear command-line evidence of the process hollowing invocation, including the full path to the Go-compiled tool and its target (`werfault.exe`). The process access events (`GrantedAccess: 0x1FFFFF`) confirm that full cross-process permissions were obtained. The dataset is useful for training detections against the command-line pattern of custom hollowing tools, process access events from PowerShell-spawned processes, and the chain of `powershell.exe → custom binary → werfault.exe`.

The main limitation is the absence of captured events documenting the actual memory manipulation steps (write, context update, resume). This is a configuration artifact rather than an execution failure — the technique ran, but Sysmon's include-mode filter did not capture the hollowing binary's own process lifecycle. Analysts building behavioral detections will benefit from the EID 10 data but should pair this dataset with memory-forensic sources for complete coverage.

## Detection Opportunities Present in This Data

1. **Command-line pattern for custom hollowing tool**: Security EID 4688 and Sysmon EID 1 both contain `C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcess.exe -program "C:\Windows\System32\werfault.exe" -debug`. Detections can target execution of unknown binaries with `-program` arguments pointing to `werfault.exe` or other LSASS/system binary targets.

2. **PowerShell spawning binaries from AtomicRedTeam paths**: The parent PowerShell command line contains `C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcess.exe`. Any PowerShell process executing binaries from non-standard paths outside `System32` or `Program Files` warrants investigation.

3. **PROCESS_ALL_ACCESS (0x1FFFFF) from PowerShell or .NET process**: Sysmon EID 10 shows `GrantedAccess: 0x1FFFFF` with a call trace passing through CLR assembly code. PowerShell opening child processes with full access rights is an anomalous pattern worth flagging, especially when the target process identity changes rapidly.

4. **werfault.exe as a child of an unexpected parent**: Legitimate `werfault.exe` invocations are spawned by `svchost.exe -k WerSvcGroup` or system crash handlers. `werfault.exe` launched as a child of a custom executable or PowerShell wrapper is an anomaly suitable for parent-child relationship detection.

5. **Defender DLL loads without active Defender scanning**: EID 7 events show `MpOAV.dll` and `MpClient.dll` loading into `powershell.exe`. In an environment where Defender is disabled, these loads still occur. The absence of follow-on Defender activity combined with these loads could indicate a tampered or bypassed security state.

6. **Named pipe creation from PowerShell with specific host process format**: Sysmon EID 17 shows `\PSHost.134180037964426843.6728.DefaultAppDomain.powershell`. While this is a normal PowerShell pipe, correlating its presence to the timing window of the hollowing event chain provides a pivot point for session reconstruction.
