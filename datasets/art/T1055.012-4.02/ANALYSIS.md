# T1055.012-4: Process Hollowing — Process Hollowing in Go using CreateProcessW and CreatePipe WinAPIs

## Technique Context

Process Hollowing (T1055.012) is a technique where an attacker creates a legitimate Windows process in a suspended state, replaces its memory image with malicious code, and resumes execution under the legitimate process's identity. This variant adds a significant wrinkle: the hollowing binary uses `CreatePipe` alongside `CreateProcessW`, establishing stdin/stdout pipe handles for the injected process. Piped process hollowing creates a communication channel between the injector and the hollowed process, enabling the attacker to pass commands in and receive output — a more operationally capable implementation than simple one-shot shellcode injection.

The use of Go for both test 3 (plain `CreateProcessW`) and test 4 (`CreateProcessW + CreatePipe`) allows direct comparison of the two variants. Adding `CreatePipe` is meaningful from an evasion perspective: it can suppress the hollowed process's console window, redirect output to avoid obvious terminal artifacts, and enable interactive operation through the established pipe channel. Attackers with capability to build custom tooling frequently prefer pipe-based implementations when they need interactive shell access through a legitimate process facade.

Detection of this variant follows the same general approach as single-stage hollowing but gains additional indicators: the pipe handles themselves (visible in handle table analysis), and the unusual combination of a parent process holding pipe read/write handles to a child process that it then injects. Sysmon's EID 17/18 (PipeCreate/PipeConnected) can surface some of these artifacts. This dataset provides the undefended baseline — the hollowing binary ran to completion, something that does not occur when Defender is active.

## What This Dataset Contains

The dataset spans five seconds (2026-03-14T23:16:52Z to 23:16:57Z) and records 144 events across four channels: Sysmon (36), PowerShell (103), Security (4), and Application (1).

**Security EID 4688 and Sysmon EID 1** capture the critical command line: the ART test framework spawns a PowerShell child with:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcessWithPipe.exe -program "C:\Windows\System32\werfault.exe" -debug}
```

The binary name `CreateProcessWithPipe.exe` — distinct from `CreateProcess.exe` in test 3 — is the primary differentiator between the two variants in the telemetry. Both target `werfault.exe` with a `-debug` flag.

**Sysmon EID 10 (ProcessAccess)** records two cross-process access events, both showing `GrantedAccess: 0x1FFFFF` (PROCESS_ALL_ACCESS). The first targets `whoami.exe` (the test framework's post-execution discovery step) and the second targets a PowerShell instance. Call traces pass through `ntdll.dll → KERNELBASE.dll → CLR assembly code`, which is consistent with managed PowerShell code making native API calls.

**Sysmon EID 7 (ImageLoad)** contributes 23 events. The pattern mirrors test 3: .NET runtime initialization (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `clrjit.dll`) followed by Defender DLL loads (`MpOAV.dll`, `MpClient.dll`) and `urlmon.dll`. This consistent pattern across both tests reflects the shared test framework environment rather than technique-specific behavior.

**Sysmon EID 2 (FileCreationTimeChanged)** appears once in test 4 but not test 3. This is a subtle distinction — a file creation time was altered during the test 4 run. File time manipulation is sometimes used to disguise newly-created hollowing artifacts as older files, although here it may also reflect Defender's own temporary file activity.

**Sysmon EID 17 (PipeCreate)** shows the test framework PowerShell creating `\PSHost.134180038107345857.4628.DefaultAppDomain.powershell`. The `-debug` flag in the command and the `CreatePipe` API call suggest that additional pipes between the injector and `werfault.exe` may have been created but are not surfaced in these Sysmon samples — the pipe logged here is the standard PowerShell host pipe.

**Security EID 4688** records all four process creation events: two for `whoami.exe` (pre- and post-test discovery) and two PowerShell instances (the attack invocation and cleanup). The security channel provides the most legible command lines but lacks the call trace depth of Sysmon.

Comparing to the defended version (36 sysmon, 10 security, 45 PowerShell), the undefended Sysmon count is identical (36) while security events drop from 10 to 4. This indicates that Defender's blocking activity in the defended run generated additional process creation events — its remediation steps rather than the technique itself accounted for the difference.

## What This Dataset Does Not Contain

As with test 3, no Sysmon EID 1 process creation event for `werfault.exe` itself appears in samples. The hollowed process either was not captured by the include-mode Sysmon filter, or its EID 1 event was not included in the sample set.

No Sysmon EID 8 (CreateRemoteThread) events are present, though this is expected — process hollowing uses `SetThreadContext` / `ResumeThread` rather than injecting a new thread, so EID 8 would not fire for the hollowing step itself.

No pipe-specific events show the actual inter-process pipe created by `CreateProcessWithPipe.exe`. The pipes created by the custom Go binary for IPC with the hollowed process are not surfaced in these Sysmon samples, which is a gap in differentiating this variant from test 3 at the event level.

The PowerShell EID 4104 samples are dominated by framework boilerplate rather than the technique invocation script block.

The Application channel has a single event (EID 15, Defender status update), consistent with the disabled-but-installed Defender state.

## Assessment

This dataset closely parallels test 3 but with the key behavioral differentiator being the binary name (`CreateProcessWithPipe.exe` vs. `CreateProcess.exe`) and the addition of a single Sysmon EID 2 (FileCreationTimeChanged) event. For detection engineering purposes, the dataset demonstrates that both pipe and non-pipe hollowing variants produce nearly identical telemetry at the Sysmon/Security level — the main forensic difference is the tool name in command-line logs. The dataset is well-suited to training process-creation-based detections and teaching analysts to differentiate hollowing tool variants by command line.

The absence of pipe-specific events means that the operational advantage of the `CreatePipe` variant — interactive process communication — is not directly visible in this telemetry. Analysts should augment this dataset with handle or ETW traces to capture the pipe lifecycle.

## Detection Opportunities Present in This Data

1. **Hollowing binary path in command line**: Security EID 4688 and Sysmon EID 1 both contain `C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcessWithPipe.exe`. Any non-standard binary executing `werfault.exe` as a child with `-program` or similar arguments is a detection candidate, regardless of the binary's name or origin path.

2. **Differentiating pipe vs. non-pipe hollowing by binary name**: Pairing this dataset with test 3 allows building a detection that fires on the broader pattern of custom executables targeting `werfault.exe`, then adds context from the binary name to classify the variant. `CreateProcessWithPipe.exe` indicates interactive capability.

3. **File creation time manipulation (Sysmon EID 2)**: The presence of EID 2 in this test but not test 3 is an opportunity to detect timestomping. A file whose creation time was modified during a known attack window, especially from the `C:\AtomicRedTeam\` path or `C:\Windows\Temp\`, is worth investigating.

4. **PROCESS_ALL_ACCESS from .NET-based process to child**: Sysmon EID 10 shows `GrantedAccess: 0x1FFFFF` with CLR call trace. PowerShell or any .NET process opening child processes with full access rights, especially following a custom binary execution, is a behavioral anomaly.

5. **werfault.exe with non-system parent**: Legitimate `werfault.exe` invocations are initiated by the system crash infrastructure. Seeing `werfault.exe` spawned by a custom Go binary or PowerShell wrapper indicates process hollowing or similar injection.

6. **Defender DLL presence without active intervention**: Both `MpOAV.dll` and `MpClient.dll` load into the PowerShell process (EID 7), but Defender performs no remediation. An environment where Defender DLLs load but no corresponding threat detection events appear may indicate a tampered security state worth flagging.
