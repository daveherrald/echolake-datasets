# T1562.002-7: Disable Windows Event Logging — Makes Eventlog Blind with Phant0m

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses a pre-compiled `Phant0m.exe` binary (included in the ART atomics repository at `C:\AtomicRedTeam\atomics\T1562.002\bin\Phant0m.exe`) to target the Windows Event Log service by killing its processing threads. Unlike T1562.002-3 which fetches Invoke-Phant0m from GitHub and uses the PowerShell variant, this test uses the compiled native binary directly, invoking it via `cmd.exe`. This is a more direct test of the underlying technique without the dependency on PowerShell execution.

## What This Dataset Contains

The dataset captures 61 events across Sysmon (16), Security (10), and PowerShell (35) channels over a four-second window.

**Sysmon Event ID 1 (process create)** records `cmd.exe` with the attack command line:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1562.002\bin\Phant0m.exe"
```

The command runs from `C:\Windows\TEMP\` under `NT AUTHORITY\SYSTEM`. The `cmd.exe` process create is captured because the sysmon-modular rules match `T1059.003` (Windows Command Shell) patterns.

**Sysmon Event ID 10 (process access)** records the ART test framework PowerShell process accessing the `cmd.exe` process with `GrantedAccess: 0x1FFFFF` (full access), tagged as `T1055.001` (DLL Injection). This is test framework-level process management behavior, not part of the attack itself.

**Security 4688/4689** records process creates and exits for `cmd.exe`, `powershell.exe`, and `conhost.exe` under SYSTEM. The `cmd.exe` exits with status `0x1` (failure), indicating that `Phant0m.exe` either was not found or failed to execute.

There are no Security 4688 events for `Phant0m.exe` itself, and no Sysmon Event ID 1 for it — `Phant0m.exe` was not recorded as a process create. Combined with the `0x1` exit code from `cmd.exe`, this indicates Windows Defender blocked the execution before the process could be created, or the binary was not present at the expected path.

**PowerShell 4104** records only the empty profile script block (test framework boilerplate). No Phant0m-related script content appears, as this is a native binary invocation rather than a PowerShell technique.

## What This Dataset Does Not Contain (and Why)

`Phant0m.exe` never executed. No process create for the binary appears in either Sysmon or Security logs, and `cmd.exe` exited with error code `0x1`. The most likely explanation is that Windows Defender (fully active with real-time protection) blocked `Phant0m.exe` when `cmd.exe` attempted to launch it. Phant0m is a known offensive tool with public signatures; Defender's blocking of such binaries typically produces a `0xC0000022` (STATUS_ACCESS_DENIED) error propagated as a non-zero exit code from the parent process.

There are no thread manipulation events (OpenThread/TerminateThread), no process access to the EventLog-hosting svchost, and no evidence of any event log service disruption.

The absence of any application log entries (unlike T1562.002-3 which showed Application events) is consistent with the binary never loading — no Windows Security Center or Defender remediation events appear in the bundled files, though Defender may have logged the block in its own event channel.

## Assessment

The technique was blocked at execution. The dataset represents the attempt pattern: the command was issued, `cmd.exe` was spawned, but `Phant0m.exe` never ran. This is a Defender block scenario — the process create command was received, but execution of the binary was prevented.

This dataset is valuable precisely because it shows what blocked attack telemetry looks like: a `cmd.exe` process create with a known offensive binary path, followed by an immediate non-zero exit code, with no child process recorded. Analysts can use the pattern of "cmd.exe creates a child that never appears in process create telemetry, and cmd.exe exits with an error" as an indicator of Defender-blocked binary execution.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** `cmd.exe` executing a path under `C:\AtomicRedTeam\atomics\` is directly detectable. The specific path `T1562.002\bin\Phant0m.exe` is a signature-level match.
- **Missing child process:** A detection rule looking for `cmd.exe` that exits with non-zero status immediately after launch without generating a child process create is a behavioral indicator of blocked binary execution.
- **Security 4689 exit code:** `cmd.exe` exiting with `0x1` immediately after launch (within <1 second based on timestamps) is anomalous.
- **Path pattern:** Any execution attempt from `C:\AtomicRedTeam\` paths or references to known offensive tool binary names in command lines should be alerted regardless of whether execution succeeded.
- **Behavioral (success case):** A successful Phant0m execution would show process access to the svchost.exe instance hosting the EventLog service with `OpenThread`/`TerminateThread`-capable access rights. This class of access to service host processes is detectable via Sysmon 10.
