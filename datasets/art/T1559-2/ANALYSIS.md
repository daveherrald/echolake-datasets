# T1559-2: Inter-Process Communication — Cobalt Strike Lateral Movement (psexec_psh) Pipe

## Technique Context

T1559 covers Inter-Process Communication as an execution channel. Test 2 emulates the named pipe pattern associated with Cobalt Strike's `psexec_psh` lateral movement module, which uses a named pipe (typically `\ADMIN$` or a generated pipe name) to communicate with a remotely deployed PowerShell payload. The psexec_psh technique is a core Cobalt Strike lateral movement primitive: the beacon copies a PowerShell one-liner to the remote system via SMB and establishes a named pipe for C2 communication back to the operator's beacon.

## What This Dataset Contains

The dataset spans 6 seconds (01:15:08–01:15:14 UTC) across 32 Sysmon events, 10 Security events, and 34 PowerShell events.

The ART test framework invokes the test via the same pattern as test 1, launching `namedpipes_executor.exe` with `--pipe 2` via `cmd.exe` under SYSTEM context:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 2
```

Security 4688 captures this command line with the full parent chain (`powershell.exe` → `cmd.exe` → executor). The `cmd.exe` process exits with status `0x1`, matching the pattern seen in tests 1, 3, and 4 — the executor is blocked before completing the pipe operation. The ART preflight `whoami.exe` is captured in both Security 4688 and Sysmon EID 1.

Two PSHost named pipes appear in Sysmon EID 17, both created by PowerShell instances in the test framework execution chain. The PowerShell 4103 module logging records the standard `Set-ExecutionPolicy Bypass` invocation.

This test generates slightly more Sysmon events (32) than test 1 (26) due to minor timing differences in test framework initialization, but the core telemetry pattern is structurally identical.

## What This Dataset Does Not Contain (and Why)

The psexec_psh pipe name that a real Cobalt Strike deployment would create — typically a random short identifier under `\\.\pipe\` — is absent. As with tests 1, 3, and 4, the ART executor simulates the connecting client, not the server side that creates the pipe. There is no live Cobalt Strike beacon in the test environment.

No lateral movement artifacts (SMB connections, remote service creation, ADMIN$ share access) appear in this dataset. The test is purely a local named pipe connection attempt. Windows Defender blocked execution before the pipe connection completed. Sysmon EID 18 (PipeConnected) is absent. No Security logon events for remote sessions appear because no lateral movement actually occurred.

The Sysmon ProcessCreate filter did not capture `namedpipes_executor.exe` because it uses include-mode matching on known suspicious patterns; this binary name does not match any rule. Security 4688 captures the `cmd.exe` wrapper but not the child executor process directly.

## Assessment

Functionally identical to test 1 at the telemetry level — the pipe number differs (`--pipe 2` vs `--pipe 1`) but the observable events are structurally the same. The dataset documents the telemetry signature of a blocked psexec_psh pipe attempt: SYSTEM-context `cmd.exe` with a suspicious binary path, immediate non-zero exit, and no pipe creation or connection events. Useful as a comparison case alongside tests 1, 3, and 4 for building detection logic that generalizes across all four Cobalt Strike pipe variants.

## Detection Opportunities Present in This Data

- **Security 4688**: Command line `namedpipes_executor.exe --pipe 2` with path traversal (`atomics\..`) from SYSTEM via `powershell.exe` → `cmd.exe`; the `ExternalPayloads\build\` path is a strong indicator.
- **Sysmon EID 1**: `whoami.exe` and `cmd.exe` spawned by SYSTEM-context `powershell.exe` in close succession; combined with the ART path, this pattern is high confidence.
- **Sysmon EID 10**: `powershell.exe` opening child processes with DLL-injection-class access rights; identical pattern across all four pipe tests.
- **Security 4689**: `cmd.exe` exit status `0x1` immediately after creation — rapid failure without output is an AV/EDR block indicator.
- **Sysmon EID 17**: Two `\PSHost.*` pipes confirm the two-stage PowerShell test framework; the absence of any non-PSHost pipe in a test explicitly about pipe IPC is itself a behavioral indicator of a blocked attempt.
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass` under SYSTEM is present in all four pipe tests; correlating this with the executor command line narrows the hunt.
