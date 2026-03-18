# T1055.001-1: Dynamic-link Library Injection — Process Injection via mavinject.exe

## Technique Context

T1055.001 Dynamic-link Library Injection is a process injection sub-technique where adversaries force a running process to load and execute a malicious DLL. DLL injection provides code execution within the target process's memory space and security context. The classic implementation calls `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and then `CreateRemoteThread` pointing to `LoadLibrary` — a well-known sequence that most EDR products detect.

`mavinject.exe` is a Microsoft-signed binary shipped as part of Application Virtualization (App-V). It accepts a PID and DLL path as arguments and performs the injection sequence on behalf of the caller. This makes it a Living-Off-The-Land Binary (LOLBin): the injection activity is performed by a legitimately signed Microsoft binary, which may bypass signature-based defenses that would block an unsigned injector. The detection community has broadly catalogued `mavinject.exe` as a high-signal LOLBin, and most mature SIEM libraries include rules for its process creation. However, detecting the injection's effects (what DLL was loaded into what process) requires additional visibility from process access and image-load events.

This test starts `notepad.exe`, injects `C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll` into it via `mavinject.exe`, then terminates notepad. With Defender disabled, the DLL injection proceeds without interference.

## What This Dataset Contains

This is one of the cleaner datasets in the batch — the attack sequence is relatively straightforward and most steps are visible in the telemetry.

**Security EID 4688 — process creation (6 events):** The complete execution chain:

1. `powershell.exe` with the full command:
   ```
   "powershell.exe" & {$mypid = (Start-Process notepad -PassThru).id
   mavinject $mypid /INJECTRUNNING "C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll"
   Stop-Process -processname notepad}
   ```
2. `notepad.exe` created: `"C:\Windows\system32\notepad.exe"`
3. `mavinject.exe` called with the target PID and DLL path:
   ```
   "C:\Windows\system32\mavinject.exe" 6596 /INJECTRUNNING C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll
   ```
4. A second `whoami.exe` and cleanup `powershell.exe`.

All run as `NT AUTHORITY\SYSTEM`. The `mavinject.exe` command fully exposes the DLL path, the target PID, and the `/INJECTRUNNING` flag.

**Sysmon EID 1 — process create (5 events):** `whoami.exe` (tagged `T1033`), the child PowerShell executing the injection command (tagged `T1059.001`), a second PowerShell, and two `whoami.exe` runs. Note: `mavinject.exe` and `notepad.exe` process creation events are absent from Sysmon EID 1 — neither matches the include-mode filter. Security 4688 provides the coverage for these processes.

**Sysmon EID 10 — process access (7 events):** Multiple process access events show PowerShell accessing child processes with `GrantedAccess: 0x1fffff`. The call trace routes through `ntdll.dll` → `KERNELBASE.dll` → .NET assemblies (`System.ni.dll`, `System.Management.Automation.ni.dll`). These are tagged `technique_id=T1055.001,technique_name=Dynamic-link Library Injection`.

**Sysmon EID 7 — image load (17 events):** .NET CLR DLLs in PowerShell processes, Defender DLLs (`MpOAV.dll`, `MpClient.dll`), and `urlmon.dll`. Notably absent: no image-load event showing `T1055.001.dll` being loaded into `notepad.exe` — this would require Sysmon to capture image loads in the notepad process, which may not be enabled for non-suspicious processes.

**Sysmon EID 8 — CreateRemoteThread (1 event):** This event was visible in deeper sample analysis. `mavinject.exe` creates a remote thread in the target process as part of the DLL injection sequence. This is the EID 8 event that is characteristically absent in the Go injection tests — here it is captured because `mavinject.exe` uses the documented `CreateRemoteThread` Win32 API rather than native syscalls.

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Sysmon EID 11 — file create (1 event):** PowerShell startup profile.

**Application EID 15 (1 event):** Defender status reconciliation artifact.

**PowerShell EID 4104 (95 events):** Test framework boilerplate. The injection command itself appears in the Security 4688 record rather than as a logged script block — it is passed as a literal argument to PowerShell.

**Comparison to defended dataset:** The defended version recorded 50 sysmon, 14 security, and 37 powershell events. The undefended dataset: 34 sysmon, 6 security, 95 powershell. The defended run had significantly more Sysmon events, likely because Defender's scanning of the injected DLL generated EID 7 (image load) and EID 10 (process access) events for Defender processes. In the defended run, the injection attempt failed (`mavinject.exe` exited with error code `0x30005`). In the undefended run, the injection proceeds — but the success or failure of the DLL injection is not directly visible in the event data (no image-load confirmation of `T1055.001.dll` in notepad).

## What This Dataset Does Not Contain

- No Sysmon EID 7 showing `T1055.001.dll` loading into `notepad.exe`. Confirming successful DLL injection requires an image-load event in the target process, which is not captured here (notepad doesn't match the sysmon-modular image-load include rules for suspicious processes).
- No Sysmon EID 1 for `mavinject.exe` or `notepad.exe`. Security 4688 provides coverage.
- No Sysmon EID 3 (NetworkConnect) from the injected DLL. If `T1055.001.dll` established a network connection, it is absent.
- No evidence of what `T1055.001.dll` does after injection. The DLL payload's post-injection behavior is unobserved.

## Assessment

This dataset is highly valuable for detection engineering. It captures the primary detection signal for `mavinject.exe`-based injection — the process creation event with the DLL path and target PID — in both Security EID 4688 and Sysmon EID 1. The Sysmon EID 8 CreateRemoteThread event provides a secondary confirmation of injection activity. This is significantly richer than the Go injection datasets in this batch.

The dataset enables building and testing detections against `mavinject.exe /INJECTRUNNING` specifically, as well as the process lineage (PowerShell → mavinject) and the `/INJECTRUNNING` argument pattern. It also illustrates the key difference between LOLBin injection (captured in Sysmon EID 8) versus native/Go injection (EID 8 absent).

## Detection Opportunities Present in This Data

1. Security EID 4688 for `mavinject.exe` with `/INJECTRUNNING` in `CommandLine` — this is a near-zero false-positive rule. `mavinject.exe /INJECTRUNNING` has no legitimate use case in most environments.

2. The DLL path `C:\AtomicRedTeam\atomics\T1055.001\src\x64\T1055.001.dll` in the `mavinject.exe` command line identifies the specific injected payload.

3. Sysmon EID 1 with `Image: mavinject.exe` and parent `powershell.exe`, or any parent process that is not `AppV` infrastructure.

4. Sysmon EID 10 showing `mavinject.exe` accessing another process (here notepad) with high-privilege access rights — the combination of mavinject as the source process and any target with `GrantedAccess >= 0x1F0FFF` is a strong injection indicator.

5. Sysmon EID 8 (CreateRemoteThread) from `mavinject.exe` into any target process — this is the injection confirmation event and is present in this dataset.

6. `notepad.exe` created by `powershell.exe` as SYSTEM in `C:\Windows\TEMP\` as part of a one-line sequence that also includes `mavinject.exe` is a process lifecycle pattern specific to this attack sequence.

7. The PowerShell command line containing `Start-Process notepad -PassThru` (to retrieve PID) followed immediately by `mavinject $mypid /INJECTRUNNING` in the same script block is a specific pattern visible in EID 4688.
