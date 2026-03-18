# T1654-2: Log Enumeration — Enumerate Windows Security Log via WevtUtil

## Technique Context

T1654 (Log Enumeration) using `wevtutil` represents a command-line approach to enumerating Windows event log structure and content. Where `Get-EventLog` (T1654-1) failed to produce telemetry, `wevtutil enum-logs` does produce process-based events because it is an external executable. Adversaries use `wevtutil` to list available logs (identifying which logs are enabled and their names) as a precursor to reading log content, clearing logs, or exporting them.

## What This Dataset Contains

This dataset captures `wevtutil enum-logs` executed via `cmd.exe` from a PowerShell test framework, as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

**Sysmon (37 events)** — EID 7 (image load) for PowerShell DLL loads; EID 17 (named pipe) for PSHost pipe; EID 10 (process access) tagged T1055.001; EID 1 (process create):
  - `whoami.exe` tagged `technique_id=T1033`
  - `cmd.exe` with command line `"cmd.exe" /c wevtutil enum-logs` — tagged `technique_id=T1059.003`
  - `wevtutil.exe` with command line `wevtutil enum-logs` — tagged `RuleName: Event Log Access` (a dedicated sysmon-modular rule for this exact behavior)
- EID 11 (file create) events for PowerShell startup profiles

**Security log (16 events)** — EID 4688 (process create) records:
  - `whoami.exe` spawned from PowerShell
  - `cmd.exe` spawned from PowerShell with command line `"cmd.exe" /c wevtutil enum-logs`
  - `wevtutil.exe` spawned from `cmd.exe` with command line `wevtutil enum-logs`
- EID 4689 process termination events for all three
- Three EID 4703 token right adjustment events for `wevtutil.exe`: the first enabling `SeSecurityPrivilege` (specifically required to read the Security log), the second enabling `SeBackupPrivilege`, and the third showing disabled privileges — reflecting the token adjustment lifecycle as the process runs and completes.

**PowerShell log (44 events)** — EID 4103 for `Set-ExecutionPolicy Bypass` and the standard test framework boilerplate stubs. No script block captures the `wevtutil` invocation itself because it runs through `cmd.exe` rather than native PowerShell.

## What This Dataset Does Not Contain (and Why)

- **Log enumeration output** — The list of event log names returned by `wevtutil enum-logs` is not captured in any event channel. The command successfully runs (exit status 0x0 from EID 4689) but output is not logged.
- **Security log content** — `wevtutil enum-logs` only lists log names, not their content. Reading log content would require `wevtutil qe` (query events), which is not part of this test.
- **Sysmon ProcessCreate for the outer PowerShell test framework** — Same filtering behavior as other datasets: the outer test framework PowerShell is not on the include list.
- **PowerShell script block for the command** — Because the test runs through `cmd.exe`, no 4104 block captures the `wevtutil` command string directly.

## Assessment

The test completed successfully. The three EID 4703 token right adjustment events for `wevtutil.exe` are particularly notable: `SeSecurityPrivilege` is specifically required to access the Security event log, and its appearance in a 4703 event for `wevtutil.exe` directly indicates that the process requested access to security-sensitive resources. The Sysmon EID 1 with `RuleName: Event Log Access` demonstrates that the sysmon-modular config has a dedicated rule for this exact behavior, providing out-of-the-box detection labeling. The contrast with T1654-1 (zero events) illustrates how process-based detection (requiring an external executable) differs fundamentally from PowerShell-native command detection.

## Detection Opportunities Present in This Data

- **Sysmon EID 1, RuleName "Event Log Access"**: The sysmon-modular config includes a dedicated rule matching `wevtutil.exe` process creation, providing immediate alert-ready labeling without custom rule development.
- **Security EID 4688**: `wevtutil.exe` with `enum-logs` command line, spawned from `cmd.exe` which is itself spawned from `powershell.exe` in a SYSTEM context, is highly anomalous for legitimate activity.
- **Security EID 4703 with SeSecurityPrivilege**: Token adjustment enabling `SeSecurityPrivilege` for `wevtutil.exe` specifically indicates log access to protected event channels. Correlating 4703 events with the preceding 4688 for `wevtutil.exe` provides a high-confidence detection chain.
- **Sequential 4703 privilege events**: The three sequential 4703 events (enable SeSecurityPrivilege → enable SeBackupPrivilege → disable) form a recognizable pattern for `wevtutil` log access operations.
- **Comparison with T1654-1**: For detection engineers, this dataset paired with T1654-1 illustrates that `wevtutil`-based log enumeration produces reliable process-based telemetry while PowerShell-native `Get-EventLog` does not, directly informing detection coverage gap analysis.
