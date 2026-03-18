# T1562.001-13: Disable or Modify Tools — AMSI Bypass - AMSI InitFailed

## Technique Context

T1562.001 (Disable or Modify Tools) includes bypassing the Antimalware Scan Interface (AMSI), which Windows uses to allow security products to scan script content at runtime — including PowerShell commands, WScript, and other scripting hosts. The AMSI InitFailed bypass patches the `amsi.dll` in-memory by causing the `AmsiInitialize` function to return a failure code (E_FAIL / 0x80070002), causing the calling script host to skip AMSI scanning for the remainder of its process lifetime. This is an entirely in-memory technique that leaves no file on disk.

This bypass was first published publicly around 2016 and has been incorporated into numerous offensive toolkits. Because it operates via memory patching, detection relies on behavioral indicators rather than file-based signatures.

## What This Dataset Contains

The dataset captures 65 events across Sysmon, Security, and PowerShell logs collected during a 5-second window on 2026-03-14 at 14:48–14:49 UTC.

Key observations from the data:

- **Sysmon EID 8 (CreateRemoteThread)**: `powershell.exe` (PID 5788) creates a remote thread in an `<unknown process>` (PID 1808) at `StartAddress: 0x00007FF6D64B4EB0` with no `StartModule` or `StartFunction`. The target process is listed as `<unknown process>`, indicating it exited (or was not fully resolved) by the time Sysmon recorded the event. This is the primary indicator of the memory-patching operation.
- **Sysmon EID 10 (ProcessAccess)**: `powershell.exe` opens `whoami.exe` with `GrantedAccess: 0x1FFFFF` — this is the ART test framework output-capture pattern, not technique-related.
- **Sysmon EID 1**: `whoami.exe` fires (T1033 rule) immediately before the bypass activity, consistent with ART pre-execution discovery.
- Sysmon EID 7 (ImageLoad) fires for the PowerShell DLL chain. Notably, `urlmon.dll` is loaded — this is part of the .NET runtime initialization sequence in PowerShell and not specific to the AMSI bypass.
- **PowerShell EID 4103**: Two `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` events — ART test framework boilerplate. The bypass technique itself executes within the existing PowerShell process and does not generate module-level logging because the patching code does not invoke named PowerShell commands.
- **PowerShell EID 4104**: Only ART error-handling scriptblocks are present. The AMSI bypass payload is not captured in scriptblock logging — this is by design, as the bypass targets the AMSI scanning layer that would have logged the payload.
- Security EID 4688 records `whoami.exe` process creation only; no additional 4688 events for the bypass operation itself since it runs within the existing PowerShell process.

The absence of the bypass payload in PowerShell scriptblock logging is itself a detection signal: the AMSI bypass succeeds in preventing AMSI-scanned logging of the malicious content.

## What This Dataset Does Not Contain (and Why)

**No AMSI bypass payload in PowerShell scriptblock logs (EID 4104).** The AMSI InitFailed bypass patches `amsi.dll` before the payload is scanned, preventing AMSI from inspecting — and thus logging — the bypass code. This is the fundamental property of a successful bypass. Defenders relying solely on PowerShell scriptblock logging for detection will observe a gap.

**No registry changes.** The InitFailed bypass is purely in-memory; no registry keys are modified.

**No new process creation for the bypass.** The patch executes within the existing PowerShell process. The only new processes are `whoami.exe` (ART test framework) and the EID 8 target process.

**No Defender block.** Windows Defender at signature version 1.445.536.0 does not block this bypass attempt. The EID 8 event confirms code execution reached the CreateRemoteThread call.

**No confirmation of bypass success.** The dataset does not contain a post-bypass action that would confirm AMSI was disabled (e.g., successful execution of a previously-blocked script).

## Assessment

This dataset captures the Sysmon behavioral footprint of an in-memory AMSI bypass. The EID 8 (CreateRemoteThread) event from `powershell.exe` into an unknown process is the most significant indicator — it reflects the memory manipulation stage of the bypass. The notable absence of bypass content in PowerShell scriptblock logs (EID 4104) is itself evidence of bypass success, making this a useful dataset for training detection logic that reasons about absences and anomalies rather than just presence of known-malicious strings. The dataset is somewhat sparse in technique-specific content because the bypass is intentionally covert.

## Detection Opportunities Present in This Data

- **Sysmon EID 8 (CreateRemoteThread)**: `powershell.exe` creating a thread in an unknown or short-lived process — `StartModule: -` and `StartFunction: -` indicate shellcode or a reflective injection pattern. Unusual for normal PowerShell operations.
- **PowerShell log gap**: Presence of `Set-ExecutionPolicy Bypass` (EID 4103) with minimal surrounding scriptblock activity, followed immediately by process access events, may indicate a bypass was executed and succeeded.
- **Sysmon EID 10**: `powershell.exe` opening `whoami.exe` with full access (0x1FFFFF) is an ART test framework artifact, but process access from PowerShell to system utilities in this way is worth correlating.
- **Behavioral anomaly**: PowerShell session with `ExecutionPolicy Bypass` that generates no meaningful scriptblock logs (only boilerplate) but does generate CreateRemoteThread activity is an indicator of an evasion technique at work.
- **AMSI telemetry**: Security products integrated with AMSI may report an `AmsiInitialize` failure if they subscribe to AMSI notifications — not present in this dataset, but a complementary detection path.
