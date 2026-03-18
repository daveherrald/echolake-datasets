# T1106-5: Native API — Run Shellcode via Syscall in Go

## Technique Context

T1106 (Native API) covers adversary invocation of Windows APIs, including the lowest-level mechanism: direct system calls (syscalls). Normally, Windows applications call documented Win32 APIs (kernel32.dll, ntdll.dll), which internally invoke syscalls with interrupt instructions. Adversaries bypass this by making direct syscalls—constructing the syscall number and arguments directly in assembly, skipping the Win32 API layer entirely.

The detection community primarily monitors at the Win32/ntdll API layer. Tools like EDR hooks, API monitoring, and AMSI operate at that layer. Direct syscalls bypass all user-mode hooks, executing kernel functions without touching the hooked copies of ntdll.dll. This is a well-documented evasion mechanism used in offensive tooling such as SysWhispers, HellsGate, and numerous C2 framework payloads.

This test runs a pre-compiled Go binary (`syscall.exe`) that executes shellcode using direct syscalls, demonstrating the technique in a language (Go) that makes syscall bypass relatively straightforward. The binary is at `C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe` and is invoked with the `-debug` flag.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled. The technique executed fully.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 4628) spawns a child PowerShell (PID 5240, tagged `technique_id=T1059.001`) with:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe -debug}
```

This child PowerShell directly executes the pre-compiled `syscall.exe` binary rather than downloading or compiling anything at runtime. The binary path (`C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe`) is test-specific but in a real attack scenario would be replaced by any pre-staged Go binary or compiled payload.

A second child PowerShell (PID 6216) appears in EID 11 evidence—likely the post-test framework cleanup shell.

**Image Loads (Sysmon EID 7):**

Seventeen DLL load events, all for the child PowerShell (PID 5240). Unlike T1106-1 through T1106-4, there are no compilation-related DLL loads (no csc.exe, no Framework assembly loads beyond the standard set). The syscall.exe binary is pre-compiled Go and imports few or no .NET DLLs.

**Process Access (Sysmon EID 10):**

Four events: PID 4628 (test framework) accesses `whoami.exe` (PID 5548) and child PowerShell (PID 5240) with `GrantedAccess: 0x1FFFFF`. The CallTrace for the child PowerShell access includes `UNKNOWN(00007FFF54C5C2A5)`, consistent with IEX/managed execution.

**Named Pipe (Sysmon EID 17):**

Two PSHost pipes:
- `\PSHost.134180056430529191.5240.DefaultAppDomain.powershell` (PID 5240)
- `\PSHost.134180056454669410.6216.DefaultAppDomain.powershell` (PID 6216)

**File Creation (Sysmon EID 11):**

Two file creation events, both PowerShell profile writes to `StartupProfileData-NonInteractive` by PID 5240 and PID 6216. No file artifacts from syscall.exe itself are captured—the binary executes and terminates without creating files in monitored paths.

**PowerShell Script Block Logging (EID 4104/4103):**

93 EID 4104 and 2 EID 4103 events. The lower total (95 events) compared to T1106-2/3/4 (102-123) is consistent with this test's simpler execution: no WinPwn module loading, no compilation, just a direct binary execution.

## What This Dataset Does Not Contain

The actual shellcode execution by syscall.exe is not logged. System calls are kernel-level operations; no Windows event log captures individual syscall invocations. The specific syscalls used by the Go binary (likely NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx or similar) do not appear anywhere in the dataset.

No Sysmon EID 3 network connection or EID 22 DNS query is present—the syscall.exe binary in its `-debug` mode does not appear to initiate network connections as part of the shellcode payload.

The syscall.exe binary itself does not appear as a Sysmon EID 1 process creation—it is launched by the child PowerShell via `Start-Process` or direct invocation, and the EID 1 for syscall.exe was not included in the sample. You see the child PowerShell's command line referencing it, but not syscall.exe's own process creation event with its hashes.

## Assessment

This dataset captures the key observable: a pre-compiled binary (`syscall.exe`) being executed via `& {<path>\syscall.exe -debug}` within a PowerShell child process. From a detection standpoint, the pre-compiled binary approach is harder to catch than runtime-compilation approaches (T1106-1, T1106-2): there is no csc.exe, no IEX/DownloadString, and no compilation artifacts. The only indicators are the binary path, the binary's hashes (if captured in an EID 1 event, which is not in this sample), and the behavioral context of PowerShell executing a binary from the AtomicRedTeam directory.

Compared to the defended variant (sysmon 28, security 4, powershell 45), the undefended dataset has similar Sysmon coverage (29) and similar Security events (4), but more PowerShell events (95 vs. 45). The defended run's lower PowerShell count suggests Defender terminates the child PowerShell before it generates as many script block events.

The direct syscall technique is one of the most challenging to detect through conventional event logging. This dataset illustrates why: the payload execution itself leaves no Windows event log trace, and the surrounding process telemetry only tells you that a binary named `syscall.exe` was run—which requires knowing the binary is malicious.

## Detection Opportunities Present in This Data

**Binary path under AtomicRedTeam\atomics\ (EID 4688 / EID 1):** The path `C:\AtomicRedTeam\atomics\T1106\bin\x64\syscall.exe` is test-specific, but the pattern of executing a binary from a staged payload directory via PowerShell's `& {<path>}` syntax is actionable. In real attacks, the binary would be in a different path (user temp, AppData, or a masqueraded location).

**Unnamed binary with `-debug` flag via PowerShell (EID 1):** A PowerShell child process executing an unsigned or unknown binary from a non-standard path with debug flags is suspicious regardless of the binary's specific name.

**Binary hash correlation (if EID 1 for syscall.exe were captured):** A pre-compiled Go binary designed for syscall-based shellcode execution would have a distinctive hash profile and low prevalence score in file reputation systems. Even without signature-based detection in Defender (disabled), a hash lookup against threat intelligence would yield a match for known offensive tools.

**Absence of expected artifacts as a negative indicator:** In environments where you expect to see specific file I/O or network activity for a given operation, the complete absence of those artifacts when a binary executes may indicate it is bypassing normal API paths. This is a behavioral anomaly indicator that requires a baseline.
