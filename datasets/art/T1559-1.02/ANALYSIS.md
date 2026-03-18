# T1559-1: Inter-Process Communication — Cobalt Strike Artifact Kit pipe

## Technique Context

Inter-Process Communication (T1559) covers adversary abuse of OS IPC mechanisms for local execution or lateral movement. Named pipes are a primary IPC mechanism in Windows and are extensively used by post-exploitation frameworks for command-and-control communication between implant components. Cobalt Strike, one of the most widely deployed adversary simulation and real-world attack frameworks, uses several distinct named pipe naming conventions for different purposes. Defenders have catalogued these pipe names and they appear in threat intelligence and detection rule sets worldwide.

This test uses the ART `namedpipes_executor.exe` utility to create the specific named pipe associated with Cobalt Strike's Artifact Kit: `\\.\pipe\isapi_http`. The Artifact Kit is Cobalt Strike's mechanism for building custom loaders and payloads; the `isapi_http` pipe name is used by default Artifact Kit-generated stagers for communication between the stager and the Beacon payload.

## What This Dataset Contains

The dataset spans approximately 3 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 119 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 1
```

The outer PowerShell test framework invokes this through `cmd.exe`. Sysmon EID 1 tags `cmd.exe` with `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, then `cmd.exe /c namedpipes_executor.exe --pipe 1`, then a second `whoami.exe`. Three EID 4688 events. The `namedpipes_executor.exe` binary itself does not appear in the Sysmon EID 1 samples (the include-mode filter does not match it by name), but it executes as a child of `cmd.exe` and creates the `isapi_http` pipe before terminating.

**Sysmon events** (16 total):
- EID 7 (Image Load): 9 events — .NET CLR assemblies loading into the test framework PowerShell process
- EID 1 (Process Create): 3 events — `whoami.exe` (twice) and `cmd.exe`, all tagged by sysmon-modular rules
- EID 10 (Process Access): 3 events — PowerShell accessing `whoami.exe` and `cmd.exe` child processes with `0x1fffff` full access, tagged `T1055.001/Dynamic-link Library Injection`
- EID 17 (Pipe Create): 1 event — the `\PSHost.*` pipe from the PowerShell test framework itself

Note: The Cobalt Strike `isapi_http` pipe created by `namedpipes_executor.exe` does not appear in the Sysmon EID 17 sample set. The sysmon-modular configuration uses an include-mode approach for named pipes, and the Cobalt Strike pipe names may be filtered or the pipe may have been created and destroyed faster than Sysmon could log it. The full `sysmon.jsonl` (16 events) would show whether EID 17 captured the named pipe creation event.

**PowerShell channel** (97 events): 96 EID 4104 script block records and 1 EID 4103. The 4103 confirms `Set-ExecutionPolicy Bypass`. The cleanup hook `Invoke-AtomicTest T1559 -TestNumbers 1 -Cleanup -Confirm:$false` is visible in a EID 4104 block.

**Application channel**: Three EID 15 Security Center reports (three Defender status pings during the test window).

**Security channel**: Three EID 4688 events.

## What This Dataset Does Not Contain

No actual Cobalt Strike Beacon is present. `namedpipes_executor.exe` is a test framework utility that creates the named pipe with the Cobalt Strike-associated name and then exits; it does not implement any C2 protocol. There is no network traffic, no shellcode, and no payload execution. The dataset simulates the named pipe artifact that a real Cobalt Strike deployment would create.

The `isapi_http` pipe creation event is not confirmed in the sample set — it may be in the full dataset (EID 17 is present in the sysmon breakdown with 1 event in the full dataset including the PSHost pipe). The Cobalt Strike artifact pipe may have been created but not captured depending on the sysmon-modular pipe filter configuration.

## Assessment

The five T1559 tests in this dataset group (T1559-1 through T1559-5) are structurally nearly identical: a PowerShell test framework invokes `cmd.exe /c namedpipes_executor.exe --pipe N`, where N determines which Cobalt Strike pipe name is created. The primary forensic value is in the process creation telemetry (Security EID 4688, Sysmon EID 1) and any named pipe creation events (Sysmon EID 17) that capture the Cobalt Strike-associated pipe names.

Compared with the defended variant (datasets/art/T1559-1, Sysmon: 26, Security: 10, PowerShell: 34), the undefended dataset has 119 total events versus 70. The defended run had more Security events (10 vs 3), likely because Defender generated additional process events when it detected and handled the Cobalt Strike-indicator pipe name. The undefended PowerShell count (97 vs 34) is much higher — the framework initialization boilerplate logs more completely when Defender is not interrupting execution.

## Detection Opportunities Present in This Data

**Named pipe creation monitoring (Sysmon EID 17)**: The creation of `\\.\pipe\isapi_http` by any process other than a known legitimate application is a direct Cobalt Strike Artifact Kit indicator. The sysmon-modular configuration should capture this if the pipe filter includes known Cobalt Strike pipe names.

**Security EID 4688 command line**: `namedpipes_executor.exe --pipe 1` combined with the path in `C:\AtomicRedTeam\ExternalPayloads\build\` is an ART-specific indicator. In a real attack, the pipe creation would come from a Beacon or stager binary with a different name, but the same pipe name would appear.

**cmd.exe spawned from a SYSTEM-context PowerShell** executing a binary in a non-standard path is a process lineage anomaly. The `ExternalPayloads\build\` path is ART-specific, but an attacker's equivalent would similarly involve an unusual binary path.

**Three Application EID 15 Security Center events** in a 3-second window suggest Defender was repeatedly checking its status during this execution — an unusually high polling rate that correlates with suspicious activity detection in the background.
