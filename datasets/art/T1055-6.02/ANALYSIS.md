# T1055-6: Process Injection — Process Injection with Go using UuidFromStringA WinAPI

## Technique Context

T1055 Process Injection covers adversary techniques that execute code within another process's address space. The `UuidFromStringA` injection method is a less commonly documented but increasingly relevant variant. The technique exploits the `UuidFromStringA` function from `rpcrt4.dll`, which converts a UUID string to binary form. An attacker encodes shellcode as a series of UUID strings, passes them to `UuidFromStringA`, and uses the fact that this function writes to a caller-specified memory address to effectively copy shellcode byte-by-byte into allocated memory. Code execution is then achieved by queuing the memory region as an APC or creating a remote thread pointing to it.

The `UuidFromStringA` technique has attracted interest in the offensive community specifically because it avoids calling `WriteProcessMemory` directly — a Win32 API that many EDR products monitor closely for cross-process writes. By delegating the write operation to a UUID decoding function, the technique sidesteps a common detection point. The technique was popularized in a blog post around 2021 and has since appeared in offensive toolkits alongside similar "indirect shellcode write" approaches using `EnumSystemLocalesA`, `EnumTimeFormatsA`, and similar functions.

The implementation here is a Go binary (`UuidFromStringA.exe`), combining Go's lack of CLR dependencies with this evasion-oriented injection method. As with other Go injection tests in this batch, detection is heavily dependent on behavioral (process access, thread creation) rather than signature-based approaches.

## What This Dataset Contains

With Defender disabled, the binary executes freely. The dataset's composition closely parallels T1055-11 and T1055-12 — the Go injection patterns produce similar telemetry footprints.

**Security EID 4688 — process creation (4 events):** The critical command line:

```
"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055\bin\x64\UuidFromStringA.exe -debug}
```

Cleanup: `Stop-Process -Name CalculatorApp -ErrorAction SilentlyContinue`, confirming Calculator as the injection target. Both execute as `NT AUTHORITY\SYSTEM`.

**Sysmon EID 7 — image load (22 events):** Standard .NET CLR and Defender DLLs in PowerShell processes. No image loads attributable to `UuidFromStringA.exe` or its injection target.

**Sysmon EID 10 — process access (4 events):** PowerShell to `whoami.exe` and child PowerShell with `GrantedAccess: 0x1fffff`. ART test framework artifacts.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` twice, child PowerShell twice. `UuidFromStringA.exe` absent from Sysmon EID 1.

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Sysmon EID 11 — file create (2 events):** PowerShell startup profile data.

**Application EID 15 (1 event):** `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — Windows Security Center status reconciliation artifact (see T1055-12 analysis).

**PowerShell EID 4104 (103 events):** ART test framework boilerplate only.

**Comparison to defended dataset:** The defended version recorded 46 sysmon, 10 security, and 53 powershell events — notably more than the undefended (35 sysmon, 4 security, 103 powershell). The defended Sysmon count was higher because Defender's own processes were actively scanning and generating EID 7 and EID 10 activity. The undefended run has fewer Sysmon events in total but more PowerShell events — the Go binary ran further without interruption, generating more PowerShell framework activity. Neither dataset captures the injection mechanism directly.

## What This Dataset Does Not Contain

As with the other Go injection tests, the injection activity itself is absent:

- No Sysmon EID 8 (CreateRemoteThread). The `UuidFromStringA` technique writes shellcode without calling `WriteProcessMemory`, and may execute it via `EnumSystemLocalesA` (APC) or similar indirect execution — neither of which Sysmon's EID 8 monitoring captures.
- No Sysmon EID 1 for `UuidFromStringA.exe`.
- No evidence of Calculator injection target process creation or access.
- No UUID strings or shellcode patterns in PowerShell script blocks.
- No memory allocation events. `VirtualAllocEx` is not directly logged by Sysmon.
- No `rpcrt4.dll` image-load events from the injection target process.

## Assessment

This dataset is primarily valuable for command-line detection testing. The `UuidFromStringA.exe` binary name and path are directly observable in Security EID 4688. The dataset's close parallel to T1055-11 and T1055-12 reinforces the pattern: Go injection tools in this test suite produce similar Sysmon footprints regardless of the injection API used, because the injector binary itself is invisible in Sysmon and the injection API calls are not captured by standard EID 8 monitoring.

The `UuidFromStringA` technique's specific evasion value — avoiding `WriteProcessMemory` — is not directly visible in this telemetry. Detection of this variant in production requires either kernel-level monitoring of `NtWriteVirtualMemory` calls, memory scanning for UUID-encoded shellcode patterns, or behavioral correlation of `rpcrt4.dll` usage with unusual process behaviors.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` containing `UuidFromStringA.exe` — the tool name is a direct, high-confidence indicator.

2. `Stop-Process -Name CalculatorApp` as a post-injection cleanup, combined with no corresponding `Start-Process` for Calculator, suggests Calculator was started and injected by the Go binary rather than by PowerShell directly.

3. The Application EID 15 Defender status event (`SECURITY_PRODUCT_STATE_ON`) appears consistently across undefended Go injection tests despite Defender being GPO-disabled. Monitoring for this event combined with known-disabled Defender policy creates a contextual anomaly signal.

4. In environments with full process creation coverage, the combination of `UuidFromStringA.exe` running as SYSTEM from PowerShell, followed by a `Stop-Process` targeting an application that should have been spawned by the injector, is a distinctive behavioral sequence.

5. `rpcrt4.dll` being loaded in an unusual context (e.g., loaded into a process that does not normally use RPC, or loaded and then followed by unusual memory writes) could surface the `UuidFromStringA` technique in environments with DLL-load monitoring.

6. The three consecutive Go injection tests (T1055-11, T1055-12, T1055-6) in this batch share the pattern of PowerShell spawning a Go binary that targets Calculator, followed by `Stop-Process CalculatorApp`. If multiple tests run in sequence, correlating injection tool executions with the Calculator process lifecycle provides a cross-test detection validation approach.
