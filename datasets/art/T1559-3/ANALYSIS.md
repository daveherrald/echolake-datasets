# T1559-3: Inter-Process Communication — Cobalt Strike SSH (postex_ssh) Pipe

## Technique Context

T1559 covers Inter-Process Communication as an execution channel. Test 3 emulates the named pipe used by Cobalt Strike's `postex_ssh` post-exploitation module, which provides an SSH client capability through a named pipe interface. In a live deployment, the beacon creates a pipe (`\postex_ssh_XXXX` or similar) and the SSH client communicates over it, tunneling SSH sessions through the C2 channel. This technique blends SSH functionality with the beacon's existing named pipe infrastructure, making it harder to distinguish SSH traffic from other beacon IPC.

## What This Dataset Contains

The dataset spans 6 seconds (01:15:24–01:15:30 UTC) across 36 Sysmon events, 10 Security events, and 42 PowerShell events. Test 3 produces slightly more events than tests 1 and 4 (which both have 26 Sysmon events) due to an additional PowerShell instance captured in the Sysmon pipe telemetry — three `\PSHost.*` pipe creation events appear instead of two, suggesting an extra PowerShell invocation during test framework execution.

The ART test framework executes:
```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 3
```

Security 4688 captures the full command line under SYSTEM context. The `whoami.exe` preflight appears in both Security 4688 and Sysmon EID 1. Sysmon EID 10 records the PowerShell process accessing child processes with DLL-injection-class access rights. `cmd.exe` exits with status `0x1`, consistent with Defender blocking the executor.

The PowerShell log has 42 events (compared to 34 in tests 1, 2, and 4), reflecting the extra PowerShell invocation captured by module and script block logging. All additional events follow the same `Set-StrictMode` / error-handler boilerplate pattern emitted at PowerShell engine startup.

## What This Dataset Does Not Contain (and Why)

No postex_ssh pipe (`\postex_ssh_*`) appears in Sysmon EID 17. The ART executor simulates the client-side connection attempt to a pipe that would normally be created by a running Cobalt Strike beacon. Without a live beacon, the server pipe was never created, and the executor had nothing to connect to before Defender terminated it.

No SSH session artifacts are present. This test exercises only the pipe IPC mechanism, not actual SSH tunneling. There are no network connection events (Sysmon EID 3) because no outbound connection was attempted or completed. There are no authentication events in the Security log.

The Sysmon ProcessCreate include filter did not fire for `namedpipes_executor.exe`. The binary name does not match the LOLBin and suspicious pattern rules in the sysmon-modular configuration, so no EID 1 event was generated for the executor itself. Security 4688 captures the `cmd.exe` wrapper with the full command line.

## Assessment

Structurally identical to tests 1, 2, and 4 at the telemetry level, with the only substantive difference being `--pipe 3` in the command line. The slightly higher event counts across Sysmon and PowerShell reflect minor test framework execution timing differences, not additional technique-specific behaviors. The postex_ssh pipe name never materializes in the data, confirming the technique was blocked. This dataset is most useful as part of a four-way comparison across the Cobalt Strike pipe variants (tests 1–4) to validate that detections generalize to all pipe types rather than relying on a specific pipe name.

## Detection Opportunities Present in This Data

- **Security 4688**: Command line `namedpipes_executor.exe --pipe 3` from SYSTEM context; the path `ExternalPayloads\build\` combined with `--pipe` arguments is the key indicator distinguishing the four pipe tests.
- **Sysmon EID 1**: `whoami.exe` spawned by SYSTEM `powershell.exe` followed closely by `cmd.exe`; this two-process ART preflight pattern is consistent across all four pipe tests.
- **Sysmon EID 10**: PowerShell accessing child processes with `T1055.001` access rights in the Sysmon-modular rule annotation.
- **Sysmon EID 17**: Three `\PSHost.*` pipe creation events; the absence of any non-PSHost pipe in a named-pipe IPC test indicates the target pipe was never created (blocked attempt signature).
- **Security 4689**: `cmd.exe` exit status `0x1` within milliseconds of creation; rapid termination pattern consistent with AV/EDR intervention.
- **PowerShell 4103**: `Set-ExecutionPolicy Bypass -Scope Process -Force` under `ACME\SYSTEM`; identical across all four tests, enabling correlation.
