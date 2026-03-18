# T1559-2: Inter-Process Communication — Cobalt Strike Lateral Movement (psexec_psh) pipe

## Technique Context

Inter-Process Communication (T1559) covers adversary abuse of Windows IPC mechanisms. This test simulates the named pipe artifact produced by Cobalt Strike's `psexec_psh` lateral movement module. The `psexec_psh` technique spawns a PowerShell payload via PsExec-style service creation on a remote host; the resulting Beacon uses a named pipe with a pattern matching `\\.\pipe\status_<random>` for local IPC between components. This pipe name pattern is associated with Cobalt Strike's lateral movement chain and appears in threat intelligence for multiple APT campaigns that use Cobalt Strike as their primary framework.

The test uses `namedpipes_executor.exe --pipe 2` to create the `status_<random>` pipe pattern locally as a simulation.

## What This Dataset Contains

The dataset spans approximately 3 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 130 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 2
```

Sysmon EID 1 tags `cmd.exe` with `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, `cmd.exe /c namedpipes_executor.exe --pipe 2`, a second `whoami.exe`, and a fourth `cmd.exe /c` (the ART cleanup step with an empty command). Four EID 4688 events total.

**Sysmon events** (18 total):
- EID 7 (Image Load): 9 events — .NET CLR assemblies into the test framework PowerShell
- EID 1 (Process Create): 4 events — `whoami.exe` (twice), the attacking `cmd.exe`, and a second `cmd.exe` for the cleanup step, both cmd.exe instances tagged `T1059.003/Windows Command Shell`
- EID 10 (Process Access): 4 events — PowerShell opening both `whoami.exe` and `cmd.exe` processes with `0x1fffff`, tagged `T1055.001/Dynamic-link Library Injection`
- EID 17 (Pipe Create): 1 event — `\PSHost.*` pipe from the test framework PowerShell

**PowerShell channel** (107 events): 104 EID 4104 blocks and 3 EID 4103 records. The 4103 records include `Set-ExecutionPolicy Bypass`, `Write-Host "DONE"`, and the pipeline execution context confirming successful completion.

**Application channel**: One EID 15 Security Center report.

**Security channel**: Four EID 4688 process creation events.

## What This Dataset Does Not Contain

No actual Cobalt Strike components are present. The `psexec_psh` pipe pattern (`status_<random>`) is simulated by `namedpipes_executor.exe`. No network connections, no service creation (which `psexec_psh` would involve on the target host), and no lateral movement activity occurred.

The named pipe created by `namedpipes_executor.exe --pipe 2` (the `status_*` pattern) is not confirmed in the Sysmon EID 17 samples — only the PSHost pipe appears. The full dataset's EID 17 breakdown is included in the 1 pipe event seen in samples, which is the PSHost pipe. The Cobalt Strike-associated pipe may have been created too briefly for the filter to capture, or the sysmon-modular pipe filter configuration does not include the `status_*` pattern.

## Assessment

T1559-2 is structurally identical to T1559-1 but targets the `psexec_psh` pipe name pattern. The `status_<random>` pipe is associated with lateral movement contexts in real Cobalt Strike deployments — specifically when a Beacon has been deployed to a remote host via PsExec and is communicating back through a named pipe channel.

The process chain here includes 4 Security EID 4688 events versus 3 in T1559-1, reflecting the additional cleanup `cmd.exe /c` event logged in this test. The PowerShell event count is higher (107 vs 97) due to additional framework pipeline execution records (3 EID 4103 vs 1).

Compared with the defended variant (datasets/art/T1559-2, Sysmon: 32, Security: 10, PowerShell: 34), the undefended dataset has 130 events total versus 76. The higher Sysmon count in the defended run (32 vs 18) likely reflects Defender detecting the Cobalt Strike pipe name and generating additional scan events. In the undefended run, there is no Defender intervention in the pipe lifecycle.

## Detection Opportunities Present in This Data

**Named pipe `status_<random>` pattern**: Any process creating a named pipe matching `\pipe\status_[a-z0-9]+` in the absence of known legitimate applications using this pattern is a Cobalt Strike lateral movement indicator. Sysmon EID 17 with this pipe name pattern is a direct detection point.

**Security EID 4688**: The complete process chain — PowerShell spawning cmd.exe executing `namedpipes_executor.exe --pipe 2` — is documented. In a real attack, the equivalent would be a Beacon binary creating the pipe; the PowerShell-to-cmd.exe-to-binary lineage from a SYSTEM context is anomalous regardless of the binary name.

**Behavioral correlation across T1559 tests**: All five T1559 tests use the same binary (`namedpipes_executor.exe`) with different `--pipe` arguments in sequence. The pipe numbers 1-5 map to distinct Cobalt Strike pipe name patterns. A defender correlating multiple pipe creation events across a short window (all five tests run within approximately 60 seconds of each other in the broader ART run) would see all Cobalt Strike pipe patterns appear on the same host in rapid succession — a clear anomaly.
