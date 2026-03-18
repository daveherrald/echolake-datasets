# T1055.004-1: Asynchronous Procedure Call — Process Injection via C#

## Technique Context

T1055.004 covers the Asynchronous Procedure Call (APC) injection sub-technique. APCs are a Windows kernel mechanism that allows threads to execute functions asynchronously when they enter an alertable wait state. Legitimate uses include I/O completion routines and timer callbacks. Attackers exploit APCs by queueing malicious code to a thread in the target process via `QueueUserAPC` (or the native `NtQueueApcThread`). When the targeted thread next calls `SleepEx`, `WaitForSingleObjectEx`, or similar alertable wait functions, it executes the queued APC — and the attacker's code runs within the target process's context.

APC injection has several behavioral characteristics that distinguish it from CreateThread-based injection. There is no `CreateRemoteThread` call (so Sysmon EID 8 may not fire), the code execution is deferred to the next alertable wait in the target thread (adding timing unpredictability), and the technique requires an appropriate target thread in an alertable state. Some implementations use "Early Bird" APC injection, where the target process is created in a suspended state and an APC is queued before the main thread fully initializes — this variant generates a distinctive process creation event for the suspended process followed by thread resumption.

The implementation here is a compiled C# binary (`T1055.exe`) executed through `cmd.exe`. C# targets are compiled to MSIL (Microsoft Intermediate Language) and run under the .NET CLR, which produces different telemetry from Go binaries: CLR initialization generates predictable image-load events (`mscoree.dll`, `clr.dll`), and the .NET runtime's process manipulation APIs leave call traces visible in Sysmon EID 10 events.

## What This Dataset Contains

The C# APC injector executes via `cmd.exe` as a child of PowerShell. The dataset captures process creation and access events.

**Security EID 4688 — process creation (4 events):** The injector command line:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1055.004\bin\T1055.exe"
```

A second `cmd.exe` with an empty command line (`"cmd.exe" /c`) appears as cleanup. Both `cmd.exe` instances are children of the PowerShell test framework. `T1055.exe` itself does not appear in Security 4688 — it is a child of `cmd.exe` but doesn't get a direct 4688 entry visible in the samples (or the process creation is below the monitoring threshold).

**Sysmon EID 1 — process create (4 events):** `whoami.exe` (twice, tagged `T1033`), and the two `cmd.exe` instances (tagged `T1059.003,technique_name=Windows Command Shell`). The first `cmd.exe` carries the full command line including `T1055.exe`. `T1055.exe` itself is absent from Sysmon EID 1.

**Sysmon EID 10 — process access (4 events):** PowerShell accessing both `whoami.exe` and `cmd.exe` instances with `GrantedAccess: 0x1fffff` (PROCESS_ALL_ACCESS). Tagged `technique_id=T1055.001`. These are ART test framework events, not the APC injector accessing its target.

**Sysmon EID 11 — file create (1 event):** `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` — an interesting variant of the PowerShell profile write (Interactive vs NonInteractive seen in other tests).

**PowerShell EID 4104 (102), EID 4103 (2):** Test framework boilerplate. Two EID 4103 (module logging) events appear — slightly different from tests that only have EID 4104.

**Comparison to defended dataset:** The defended version recorded 24 sysmon, 10 security, and 34 powershell events. The undefended dataset: 9 sysmon, 4 security, 104 powershell events. The Sysmon event count drops sharply in the undefended run: only 9 events versus 24. This is unusual and may reflect the C# binary executing quickly and cleanly when unblocked, without generating the Defender scan artifacts that inflated the defended count. The absence of Sysmon EID 7 (image load) events in the undefended dataset is notable — the C# injector should trigger CLR DLL loads, but those loads happen inside `T1055.exe`, which is not in the Sysmon image-load monitoring scope.

## What This Dataset Does Not Contain

- No Sysmon EID 7 image loads from `T1055.exe` (the injector is not covered by image-load rules).
- No Sysmon EID 8 (CreateRemoteThread). APC injection does not use `CreateRemoteThread`, confirming the absence here.
- No Sysmon EID 10 from `T1055.exe` to its injection target. The injector process is not tracked by Sysmon.
- No evidence of the injection target process. The APC injection test presumably targets an existing process (commonly a suspended process or a running application), but no target process creation or access is visible.
- No post-injection activity. The injected payload's behavior is unobserved.
- No indication of whether `T1055.exe` exited with success or failure.

## Assessment

This dataset has limited visibility into the actual APC injection mechanism. The primary value is the Security EID 4688 and Sysmon EID 1 evidence of `cmd.exe /c T1055.exe` execution, which documents the injection tool being launched. The complete absence of injection-phase artifacts (process access to target, APC queue events, thread execution in target) means this dataset can test command-line detections for the injector invocation but cannot validate behavioral detections for the APC injection technique itself.

The sharp drop in Sysmon event count between the defended (24) and undefended (9) runs is worth noting. It suggests that Defender's defensive activity around C# binaries generates substantial Sysmon telemetry (scanning, temp file creation, timestamp changes) that is absent when Defender is disabled. Detection engineers should be aware that some Sysmon events in defended environments are Defender-generated rather than attacker-generated.

## Detection Opportunities Present in This Data

1. Sysmon EID 1 `CommandLine` for `cmd.exe` containing `C:\AtomicRedTeam\atomics\T1055.004\bin\T1055.exe` — the full binary path is preserved.

2. `cmd.exe /c` followed by a path to a binary in `C:\AtomicRedTeam\atomics\` — any execution from this path structure is test-environment-specific but in production, binaries in non-standard directories launched from PowerShell via `cmd.exe /c` warrant examination.

3. Sysmon EID 10 with `GrantedAccess: 0x1fffff` from PowerShell to `cmd.exe` (the injector's parent) is an indirect signal: PROCESS_ALL_ACCESS on a `cmd.exe` process from PowerShell is consistent with the test framework's child process management but could also represent process manipulation.

4. The `StartupProfileData-Interactive` file creation in the PowerShell profile path distinguishes interactive PowerShell sessions from the `NonInteractive` variant. If this test is run interactively rather than via guest agent, the profile variant changes — this distinction can help attribute execution context.

5. In environments with C# injection tool signatures, the specific hash of `T1055.exe` (`SHA1=13E9BB7E85FF9B08C26A440412E5CD5D296C4D35` for `cmd.exe`, and the hash of `T1055.exe` itself if captured) can anchor threat hunt queries.

6. For APC injection specifically, the detection approach that this dataset does not cover but that would be most valuable: monitoring for `NtQueueApcThread` calls via kernel callbacks or ETW (Event Tracing for Windows) providers. Standard Sysmon does not capture APC queuing; this is a gap that only ETW-based or kernel-mode sensors can fill.
