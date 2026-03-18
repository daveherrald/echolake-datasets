# T1055.002-1: Portable Executable Injection — Portable Executable Injection

## Technique Context

T1055.002 Portable Executable Injection is a process injection sub-technique where adversaries inject an entire Portable Executable (PE) file — a complete Windows `.exe` — into the memory space of a running process. This is conceptually different from shellcode injection or DLL injection: instead of injecting a small piece of code or a relocatable library, the attacker maps a full PE image into the target process and redirects execution to its entry point. PE injection requires parsing the PE headers, allocating appropriately-sized memory, handling relocations, and patching imports — a more complex operation than simpler injection methods, but one that enables running a full executable within a host process without writing to disk.

PE injection is favored by advanced malware that wants to execute a payload in memory with no corresponding file on disk. The payload runs with the host process's identity and security context, and process-listing tools show the legitimate host process name rather than the malicious payload's name. `notepad.exe` is a common choice for a host process because it is benign, rarely produces suspicious network connections, and is consistently available.

The ART test uses `RedInjection.exe` — a purpose-built PE injection tool in the `C:\AtomicRedTeam\atomics\T1055.002\bin\` directory. The injection sequence typically involves opening the target process, allocating memory for the PE, writing the PE sections, applying relocations, and creating a remote thread at the PE's entry point. The `Start-Process` PowerShell cmdlet is used to launch the injector, with a 7-second sleep to allow injection to complete before killing `notepad`.

## What This Dataset Contains

With Defender disabled, `RedInjection.exe` executes without being blocked. The dataset is richer than the Go injection tests because the injector appears in Security EID 4688 telemetry (launched via `Start-Process` in PowerShell, which creates a directly observable process).

**Security EID 4688 — process creation (4 events):** Two pairs document execution:

1. Child PowerShell executing:
   ```
   "powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\T1055.002\bin\RedInjection.exe"
   Start-Sleep -Seconds 7
   Get-Process -Name Notepad -ErrorAction SilentlyContinue | Stop-Process -Force}
   ```
2. Cleanup PowerShell: `Get-Process -Name Notepad -ErrorAction SilentlyContinue | Stop-Process -Force`

The `RedInjection.exe` binary itself does not appear in Security EID 4688 — it is launched via `Start-Process` inside the PowerShell command, which creates it as a direct child of `powershell.exe`. Because it's not spawned through `cmd.exe` and the Security 4688 is logged for the PowerShell process itself, the `RedInjection.exe` process creation may be captured elsewhere or may be missing.

**Sysmon EID 7 — image load (23 events):** Standard .NET CLR and Defender DLLs in PowerShell processes.

**Sysmon EID 10 — process access (4 events):** PowerShell to `whoami.exe` and child PowerShell with `GrantedAccess: 0x1fffff`. ART test framework artifacts.

**Sysmon EID 1 — process create (4 events):** `whoami.exe` (twice), child PowerShell instances. `RedInjection.exe` and `notepad.exe` are absent from Sysmon EID 1 (include-mode filter).

**Sysmon EID 17 — named pipe create (3 events):** PowerShell host pipes.

**Sysmon EID 11 — file create (2 events):** PowerShell startup profile data.

**Application EID 15 (3 events):** Three `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` events — the highest count of Defender status events across the Go/PE injection tests. This suggests more status reconciliation activity during this test's longer execution window (7-second sleep).

**PowerShell EID 4104 (103), EID 4100 (1):** Test framework boilerplate plus one pipeline error event (EID 4100). The EID 4100 error likely corresponds to the `Stop-Process` failing if notepad had already been terminated by the injected payload.

**Comparison to defended dataset:** The defended version recorded 49 sysmon, 12 security, 47 powershell, and 2 application events — notably more sysmon and security events than the undefended (36, 4, 104, 3 respectively). In the defended run, Defender blocked `RedInjection.exe` with a PowerShell EID 4100 error: "This command cannot be run due to the error: Operation did not complete successfully because the file contains a virus or potentially unwanted software." Defender's scanning of the blocked binary generated additional Sysmon EID 2 (timestamp change by MsMpEng) and EID 11 (temp file creation by MsMpEng) events. In the undefended run, these Defender scan artifacts are absent, and the binary executes.

## What This Dataset Does Not Contain

- No Sysmon EID 8 (CreateRemoteThread) showing the PE injector creating a thread in `notepad.exe`. PE injection tools may use different execution transfer mechanisms (e.g., `SetThreadContext`, APC queuing, entry point patching) rather than `CreateRemoteThread`, depending on implementation.
- No Sysmon EID 1 for `RedInjection.exe`. Include-mode filtering misses it.
- No image-load events showing the injected PE loading into notepad's address space.
- No network activity from the injected PE. Whether the injected payload made network connections is unknown.
- No Sysmon EID 10 events from `RedInjection.exe` accessing `notepad.exe`. The process access during injection is not captured.

## Assessment

This dataset captures the essential command-line evidence of the PE injection attempt (the PowerShell command referencing `RedInjection.exe`) and confirms the 7-second execution window that allows the injection to complete. However, the injection's actual artifacts — the process access, memory allocation, and thread creation in notepad — are absent. The dataset is more useful for command-line-based detection development than for building behavioral injection detections.

The contrast with the defended dataset is instructive: Defender's error message ("file contains a virus") in EID 4100 is itself a useful detection signal that is absent in the undefended version. Teams building detections in environments with Defender can use EID 4100 content for early warning; in Defender-disabled environments, they must rely on process creation and behavioral indicators.

## Detection Opportunities Present in This Data

1. Security EID 4688 `CommandLine` for the child PowerShell containing `Start-Process "C:\AtomicRedTeam\atomics\T1055.002\bin\RedInjection.exe"` — the binary name and path are directly observable.

2. `Start-Process` followed by `Start-Sleep -Seconds 7` followed by `Stop-Process` targeting a commonly-used host process (`Notepad`) is a recognizable injection test framework pattern: launch injector, wait for injection to complete, kill host.

3. PowerShell EID 4100 (pipeline execution failure) combined with a preceding `Start-Process` for a suspicious binary can indicate that the binary was blocked by security controls — useful for building blocked-execution detection in environments with active Defender.

4. The three Application EID 15 Defender status events during a test with a 7-second sleep window provide a timing marker. Multiple EID 15 events in rapid succession may correlate with extended offensive tool execution windows.

5. In environments with full process creation coverage, `RedInjection.exe` launching as a child of `powershell.exe` running as SYSTEM from `C:\Windows\TEMP\` would be the primary process creation indicator.

6. Sysmon EID 10 from `RedInjection.exe` to `notepad.exe` (if EID 10 monitoring captures the injector's process access) with a high-privilege access mask would be the injection preparation indicator — but this requires Sysmon to capture processes not currently in the include filter.
