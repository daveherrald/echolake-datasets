# T1559-3: Inter-Process Communication — Cobalt Strike SSH (postex_ssh) pipe

## Technique Context

Inter-Process Communication (T1559) covers adversary abuse of Windows IPC mechanisms. This test simulates the named pipe created by Cobalt Strike's `postex_ssh` post-exploitation module. Cobalt Strike's SSH capability allows a Beacon to proxy SSH connections or run SSH-based lateral movement; the resulting activity creates a named pipe matching `\\.\pipe\postex_ssh_<random>` for communication between the SSH module and the Beacon process. This pipe pattern has been observed in real-world Cobalt Strike deployments and is documented in threat intelligence for financially motivated threat actors.

The test uses `namedpipes_executor.exe --pipe 3` to simulate the `postex_ssh_<random>` pipe creation.

## What This Dataset Contains

The dataset spans approximately 3 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 130 events across PowerShell, Security, and Sysmon channels (no Application channel events in this test).

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 3
```

Sysmon EID 1 tags `cmd.exe` with `technique_id=T1059.003,technique_name=Windows Command Shell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, `cmd.exe /c namedpipes_executor.exe --pipe 3`, a second `whoami.exe`, and a cleanup `cmd.exe /c` (empty command). Four EID 4688 events.

**Sysmon events** (19 total):
- EID 7 (Image Load): 9 events — .NET CLR assemblies into the test framework PowerShell
- EID 1 (Process Create): 4 events — `whoami.exe` (twice), the `cmd.exe` running `namedpipes_executor.exe --pipe 3`, and the cleanup `cmd.exe`
- EID 10 (Process Access): 4 events — PowerShell accessing child processes with `0x1fffff` full access, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): 1 event — file creation in the test framework context (likely SYSTEM profile PowerShell data)
- EID 17 (Pipe Create): 1 event — `\PSHost.*` pipe from the test framework PowerShell

**PowerShell channel** (107 events): 104 EID 4104 blocks and 3 EID 4103 records. The pipeline execution log confirms `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. Host ID `a5b06e82-2b0d-4f85-8a58-d8a46fd10413` identifies this specific PowerShell host instance.

**Security channel**: Four EID 4688 process creation events.

## What This Dataset Does Not Contain

No SSH activity, no lateral movement, and no actual Cobalt Strike components are present. The `postex_ssh_<random>` pipe pattern is simulated by the test executor utility. No network connections were made during this test.

The `postex_ssh_*` named pipe itself does not appear in the Sysmon EID 17 samples — only the PSHost pipe appears in the sample. As with T1559-1 and T1559-2, the Cobalt Strike-associated pipe may have been created and destroyed before Sysmon logged it, or the sysmon-modular filter configuration does not capture it.

The File Create event (EID 11) in this dataset is the only T1559 test (other than T1559-3's one EID 11) that shows a file creation, though it is a PowerShell initialization artifact rather than attack-generated content.

## Assessment

T1559-3 is structurally identical to T1559-2 with a different `--pipe` argument. The `postex_ssh` pipe name is operationally relevant because SSH-based lateral movement through a Cobalt Strike Beacon is a technique used in supply chain attacks and long-term persistence operations. The `postex_ssh_<random>` pipe pattern is distinguishable from the Artifact Kit and psexec_psh pipes by prefix.

The 19 Sysmon events (vs 18 in T1559-2, 16 in T1559-1) reflects one additional EID 11 file creation event in this test run. The overall structure is consistent across the T1559 group.

Compared with the defended variant (datasets/art/T1559-3, Sysmon: 36, Security: 10, PowerShell: 42), the undefended dataset has 130 events versus 88. The defended run again shows more Sysmon events (36 vs 19) — likely due to Defender activity around the pipe creation — and fewer PowerShell events (42 vs 107), consistent with Defender interrupting the PowerShell session earlier in the defended case.

## Detection Opportunities Present in This Data

**Named pipe `postex_ssh_<random>` pattern**: A named pipe matching `\pipe\postex_ssh_[a-z0-9]+` created by any process is a Cobalt Strike post-exploitation indicator. This pattern appears in threat intelligence for multiple threat actors using Cobalt Strike's SSH module.

**Security EID 4688 and Sysmon EID 1**: The full execution chain is documented. The `cmd.exe /c namedpipes_executor.exe --pipe 3` command maps to the `postex_ssh` test; in a real attack the pipe creation would come from a Beacon DLL or shellcode rather than this utility.

**Process access pattern (Sysmon EID 10)**: PowerShell accessing both `whoami.exe` and `cmd.exe` child processes with `0x1fffff` full access rights in a SYSTEM context, tagged with `T1055.001/Dynamic-link Library Injection`, is a recurrent pattern across all T1559 tests. While this access pattern is generated by the ART test framework rather than the attack itself, it represents the kind of process interaction that would accompany a real Cobalt Strike deployment.

**Cross-test correlation**: T1559-1 through T1559-5 all use the same delivery chain within a ~60-second window in the broader dataset. An analyst reviewing this host's timeline would see five distinct Cobalt Strike pipe name patterns created in rapid succession — a pattern that would not appear in legitimate Cobalt Strike usage.
