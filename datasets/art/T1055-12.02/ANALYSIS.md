# T1055-12: Process Injection — Process Injection with Go using CreateThread WinAPI (Natively)

## Technique Context

T1055 Process Injection encompasses techniques where adversaries inject code into running processes to evade detection, inherit privileges, or execute within a trusted process context. This test is closely related to T1055-11 (Go CreateThread injection) but uses a "native" variant: `CreateThreadNative.exe`. The distinction matters from a detection standpoint. The standard variant typically uses the standard Windows API (`CreateRemoteThread` via `kernel32.dll`), while a "native" implementation calls the underlying `NtCreateThreadEx` syscall directly via `ntdll.dll`, bypassing the higher-level API layer that some security tools hook. Native syscall injection reduces the number of user-mode hooks that endpoint agents can intercept.

Go's native syscall injection is a technique favored by offensive tools seeking to avoid user-mode AV/EDR hooks on `CreateRemoteThread`. By calling `NtCreateThreadEx` (or similar Nt-prefixed functions) directly from `ntdll.dll` rather than through the documented Win32 API, the injector bypasses any hooks placed on `kernel32.dll` or `kernelbase.dll` by security products. This represents a meaningful increase in evasion capability over the standard CreateThread approach.

The combination of a Go binary (no CLR dependencies, statically linked) with native syscall injection (bypasses common API hooks) makes this variant harder to detect through signature or hook-based approaches. Detection relies primarily on behavioral indicators: process access patterns, anomalous thread creation in target processes captured at the kernel level, and command-line evidence of the injector being launched.

## What This Dataset Contains

**Security EID 4688 — process creation (4 events):** The injection binary is identified in a child `powershell.exe` command line:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThreadNative.exe -debug}
```

The `-debug` flag is present as in the standard variant, and cleanup is `Stop-Process -Name CalculatorApp -ErrorAction SilentlyContinue`, confirming Calculator as the injection target. All execute as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 7 — image load (23 events):** .NET CLR DLLs load into the PowerShell orchestration processes. `CreateThreadNative.exe` generates no CLR image-load events, consistent with its Go-native construction.

**Sysmon EID 10 — process access (4 events):** PowerShell accessing `whoami.exe` and child PowerShell with `GrantedAccess: 0x1fffff`. These are ART test framework artifacts, not direct evidence of the injection tool accessing its target.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` and child PowerShell instances. `CreateThreadNative.exe` does not appear.

**Sysmon EID 2 — file creation time changed (1 event):** One file timestamp modification event appears (details not in samples). This may reflect Defender's scan activity on the binary during test setup.

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Sysmon EID 11 — file create (1 event):** PowerShell startup profile.

**Application EID 15 (1 event):** `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — this is a status reporting event from Windows Security Center, appearing despite Defender being policy-disabled. It reflects the security center's periodic status reconciliation rather than Defender actually re-enabling itself.

**PowerShell EID 4104 (103 events):** ART test framework boilerplate only.

**Comparison to defended dataset:** The defended version recorded 36 sysmon, 10 security, and 45 powershell events. The undefended dataset records 36 sysmon, 4 security, and 103 powershell events — nearly identical Sysmon counts. This mirrors the T1055-11 pattern: Defender's disablement does not materially change the Sysmon telemetry profile for Go injection tools, because the injector itself was invisible in Sysmon even in the undefended run. The additional PowerShell events in the undefended run likely reflect the tool executing more completely before PowerShell finishes.

## What This Dataset Does Not Contain

The dataset lacks the injection activity itself:

- No Sysmon EID 8 (CreateRemoteThread) events. The native implementation may use `NtCreateThreadEx` rather than `CreateRemoteThread`, and Sysmon's EID 8 monitoring hooks `CreateRemoteThread` at the API level — a native syscall implementation may bypass this monitoring entirely. This is a significant gap.
- No Sysmon EID 1 for `CreateThreadNative.exe`.
- No process access events from the injector to Calculator's process space.
- No evidence of the CalculatorApp injection target existing or being affected.
- No memory allocation events (no Sysmon event type captures `VirtualAllocEx` or `WriteProcessMemory` directly in this configuration).

## Assessment

This dataset highlights the detection gap created by native syscall injection. Even with Sysmon's CreateRemoteThread monitoring active, a Go binary using `NtCreateThreadEx` may leave no Sysmon EID 8 trace. The dataset's value is primarily in demonstrating this gap and providing command-line evidence of the technique's invocation. It is directly comparable to T1055-11 — the two datasets together illustrate that the standard and native Go variants produce nearly identical Sysmon footprints, suggesting that neither is being captured at the injection API level in this configuration.

The Application EID 15 Defender status event is an interesting artifact — it will appear in undefended datasets even when Defender is GPO-disabled, because Windows Security Center still reports status. This is worth filtering in detection logic to avoid treating it as evidence that Defender is active.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` containing `CreateThreadNative.exe -debug` — the binary name and path `C:\AtomicRedTeam\atomics\T1055\bin\x64\CreateThreadNative.exe` are direct indicators in this environment.

2. `Stop-Process -Name CalculatorApp` as a cleanup action following Go injection binary execution implies prior successful injection into a Calculator process; this cleanup pattern is a behavioral indicator.

3. Application EID 15 (`SECURITY_PRODUCT_STATE_ON`) appearing in an environment where Defender is confirmed disabled via GPO warrants investigation if it appears during active attack sequences — it can indicate a defender re-enable attempt or simply status reconciliation.

4. The absence of Sysmon EID 8 following a known injection binary execution is a signal that the injection technique uses native syscalls rather than the documented Win32 API. This absence pattern can itself be used to fingerprint native injection tools.

5. Sysmon EID 10 from PowerShell to child processes with PROCESS_ALL_ACCESS, where the parent PowerShell launched a Go binary, provides a partial correlation chain even without direct injection event capture.

6. In environments where Sysmon ProcessCreate captures all processes, the combination of a Go-compiled binary (identifiable by large static binary size, absence of CLR imports, and characteristic Go runtime stack traces in crash dumps) executing as SYSTEM from `C:\Windows\TEMP\` is a meaningful anomaly.
