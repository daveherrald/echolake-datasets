# T1559-4: Inter-Process Communication — Cobalt Strike post-exploitation pipe (4.2 and later)

## Technique Context

Inter-Process Communication (T1559) covers adversary abuse of Windows IPC mechanisms. This test simulates the named pipe used by Cobalt Strike version 4.2 and later for post-exploitation module communication. Starting with version 4.2, Cobalt Strike changed the named pipe naming convention for its post-exploitation modules (e.g., `screenshot`, `keylog`, `hashdump`) from the older `mojo.*` pattern to a new `postex_<random>` pattern. The `postex_<random>` pipe is created when a post-exploitation job is run via the Beacon, connecting the job process back to the main Beacon for data exfiltration. This pipe pattern is present in threat intelligence for Cobalt Strike deployments post-2020.

The test uses `namedpipes_executor.exe --pipe 4` to simulate the `postex_<random>` pipe creation.

## What This Dataset Contains

The dataset spans approximately 3 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 130 events across PowerShell, Security, and Sysmon channels (no Application channel events).

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 4
```

Sysmon EID 1 tags `cmd.exe` with `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, `cmd.exe /c namedpipes_executor.exe --pipe 4`, a second `whoami.exe`, and a cleanup `cmd.exe /c` (empty). Four EID 4688 events.

**Sysmon events** (19 total):
- EID 7 (Image Load): 9 events — .NET CLR assemblies into the test framework PowerShell
- EID 1 (Process Create): 4 events — `whoami.exe` (twice), the attacking `cmd.exe`, and the cleanup `cmd.exe`
- EID 10 (Process Access): 4 events — PowerShell accessing child processes with `0x1fffff`, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): 1 event
- EID 17 (Pipe Create): 1 event — `\PSHost.*` pipe from the test framework PowerShell

**PowerShell channel** (107 events): 104 EID 4104 blocks and 3 EID 4103 records. Host ID `c7d9f3c9-1252-49f9-8697-5c44b4e65241` identifies this PowerShell instance. The pipeline log confirms `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`.

**Security channel**: Four EID 4688 process creation events.

## What This Dataset Does Not Contain

No Cobalt Strike post-exploitation activity occurred. The `postex_<random>` pipe is simulated. No screenshot, keylogging, credential dumping, or other post-exploitation module output is present. There are no network connections in this dataset.

The `postex_*` named pipe itself is not confirmed in the Sysmon EID 17 samples — only the PSHost pipe appears. This is consistent with the pattern across T1559-1 through T1559-5 where the Cobalt Strike-associated pipe creation is not visible in the sampled Sysmon events.

## Assessment

T1559-4 represents the Cobalt Strike 4.2+ post-exploitation pipe pattern, which is the current convention for active Cobalt Strike deployments. The version distinction (4.2+ vs pre-4.2 in T1559-5) matters for detection because threat intel that relies on the older `mojo.*` pattern would miss current Cobalt Strike deployments, while rules targeting `postex_*` would catch them.

The dataset is structurally identical to T1559-2 and T1559-3 in terms of event counts and types (19 Sysmon, 4 Security EID 4688, 107 PowerShell). The only distinguishing characteristic between these tests in the telemetry is the `--pipe 4` argument (versus `--pipe 3` or `--pipe 2`) in the Security EID 4688 command line.

Compared with the defended variant (datasets/art/T1559-4, Sysmon: 26, Security: 10, PowerShell: 34), the undefended dataset shows the same structural pattern as the other T1559 comparisons: fewer Sysmon events when undefended (Defender's scan events inflate the defended count), and many more PowerShell events undefended (Defender terminates the session earlier in the defended run).

## Detection Opportunities Present in This Data

**Named pipe `postex_<random>` pattern (Sysmon EID 17)**: A named pipe matching `\pipe\postex_[a-z0-9]+` created by any process is an indicator specific to Cobalt Strike 4.2 and later. This is distinct from the pre-4.2 `mojo.*` pattern (tested in T1559-5) and from the `postex_ssh_*` pattern (T1559-3). Sysmon EID 17 with this pipe name pattern is a direct detection point for current Cobalt Strike deployments.

**Version-aware detection**: The `postex_*` vs `mojo.*` distinction allows attribution of Cobalt Strike version. Security operations teams tracking adversary tooling versions can use this pattern to assess whether a detection matches a known threat actor's toolkit.

**Security EID 4688**: The process chain from PowerShell → cmd.exe → `namedpipes_executor.exe --pipe 4` documents the test. In production, the equivalent `postex_*` pipe would be created by a Beacon executing a post-exploitation job; the parent process would be the Beacon binary (often injected into a host process), making the lineage more complex but the pipe name itself equally visible.

**Correlation with T1559-5**: The `postex_*` pipe (version 4.2+) and the `mojo.*` pipe (pre-4.2) tests run in rapid succession in the broader ART dataset. Seeing both patterns on the same host at approximately the same time would be impossible in a real Cobalt Strike deployment (a single installation uses one or the other), indicating a testing or red team scenario rather than a live attack — a useful false-positive reduction heuristic.
