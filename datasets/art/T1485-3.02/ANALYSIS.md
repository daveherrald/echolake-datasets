# T1485-3: Data Destruction — Overwrite deleted data on C drive

## Technique Context

T1485 (Data Destruction) covers adversary operations that permanently eliminate data to disrupt availability or obstruct forensic investigation. Unlike ransomware encryption (T1486), which preserves data in an inaccessible state for leverage, wiping is purely destructive — used in wiper attacks, sabotage campaigns, and as an anti-forensic operation at the end of an intrusion to prevent recovery.

Test T1485-3 uses `cipher.exe /w:C:` — the Windows EFS command-line tool's wipe mode — to overwrite all free space sectors on the C: drive with zeros, then ones, then random data. This makes previously deleted files forensically unrecoverable, eliminating evidentiary artifacts from the drive's unallocated space. `cipher.exe /w` is a built-in Windows utility, making it a living-off-the-land anti-forensic tool. Defenders monitor for it to detect end-of-incident cleanup operations and deliberate evidence destruction.

Note that `cipher.exe /w` only overwrites *free space* (sectors not currently used by live files) — it does not destroy currently-allocated data. Its use as an attack tool is specifically to eliminate deleted files, temporary artifacts, and previously cleared tools from forensic recovery.

## What This Dataset Contains

This dataset captures the execution of `cipher.exe /w:C:` running as `NT AUTHORITY\SYSTEM`. The operation ran for approximately 125 seconds (from 22:33:46 to 22:35:51 UTC) before being interrupted, consistent with the time needed to wipe free space on even a modest drive.

**Security EID 4688** provides the complete process chain:

```
powershell.exe → "cmd.exe" /c cipher.exe /w:C: → cipher.exe /w:C:
```

The `cmd.exe` invocation event is present with full command line. `cipher.exe` itself is captured in a subsequent EID 4688 event (`cipher.exe /w:C:`), confirming the process was spawned and ran.

Two `whoami.exe` test framework events bracket the technique execution.

**Sysmon EID 1** captures three process creation events: `whoami.exe`, `cmd.exe` (tagged `technique_id=T1059.003,technique_name=Windows Command Shell`), and the parent PowerShell context. Note that `cipher.exe` itself does not appear as a Sysmon EID 1 event — the sysmon-modular include-mode ProcessCreate filter does not have a rule matching `cipher.exe`, so its process creation is filtered from the Sysmon output. The process creation IS captured in Security EID 4688 however.

**Sysmon EID 10** (ProcessAccess): Six events show `powershell.exe` accessing `whoami.exe`, `cmd.exe`, `conhost.exe`, and `cipher.exe` with `GrantedAccess 0x1FFFFF` (full access). The `cipher.exe` process access event is significant — it confirms the test framework monitored the running cipher process, and the subsequent `0xFFFFFFFF` exit code implies the test framework terminated it after its configured timeout.

**Sysmon EID 17** captures the PowerShell named pipe, and **Sysmon EID 11** records the PowerShell profile write.

**Sysmon EID 7** (ImageLoad): 6 image load events document DLLs loaded by `powershell.exe` during the execution.

**System EID 7040**: The Background Intelligent Transfer Service (BITS) start type was changed from automatic to demand start. This is background OS activity unrelated to the technique — BITS service startup type changes occur periodically due to Windows Update scheduling adjustments.

**WMI EID 5858**: A WMI query failure is recorded: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` with result code `0x80041032` (WBEM_E_NOT_FOUND). This is the ART test framework's PowerShell remoting readiness check — it polls for `wsmprovhost.exe` via WMI to verify the remoting infrastructure, and the query fails because the class `Win32_ProcessStartTrace` is unavailable in the WMI namespace on this configuration.

The PowerShell channel (131 events: 116 EID 4104 + 15 EID 4103) is larger than typical test framework-only runs. The 15 EID 4103 module logging events and the elevated 4104 count may reflect CIM module loading as part of the WMI-based process monitoring the test framework performs.

**Compared to the defended variant** (33 Sysmon / 30 Security / 58 PowerShell / 1 system / 1 wmi): The undefended run has fewer events across all channels (18 Sysmon / 5 Security / 131 PowerShell / 1 system / 1 wmi). The defended variant's higher Security count (30 vs. 5) is notable and likely reflects Defender-generated process access events during scanning of `cipher.exe`. Since Defender does not actually block `cipher.exe /w`, both runs complete the wipe operation. The undefended run's lower Security count simply reflects the absence of Defender's monitoring overhead.

## What This Dataset Does Not Contain

The extent of the wiping operation itself is not captured. There are no file-level telemetry events showing which sectors or deleted files were overwritten — `cipher.exe /w` operates at the block level, and Windows event logging does not record individual sector writes. No Security EID 4663 (object access) events exist because object access auditing is disabled. The dataset captures only the invocation, not the destruction. If `cipher.exe` ran for approximately 125 seconds, it overwrote a significant portion of the drive's free space — but this is inferred from timestamps, not from logged events.

The reason `cipher.exe` exited with `0xFFFFFFFF` (interrupted) rather than `0x0` (completed) is that the ART test framework imposed a timeout and killed it. A real attacker would let it run to completion; detection based solely on exit codes would miss a fully-completed wipe operation.

## Assessment

This dataset provides strong invocation evidence for the `cipher.exe /w` data destruction technique. Both Security and Sysmon capture the `cmd.exe` command line that drives the operation, and Security captures the `cipher.exe` process itself. The `0xFFFFFFFF` exit code on `cipher.exe` combined with the `powershell.exe → cmd.exe → cipher.exe` parent chain in process access events tells the complete operational story: the process ran, was monitored by the test framework, and was killed before completion. In a real incident, the `0x0` clean exit would be present instead.

The WMI and System channel artifacts (EID 5858, EID 7040) are background noise worth noting — they represent platform-level activities that co-occur during any ART test session and should not be interpreted as technique artifacts.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `cipher.exe /w:C:` or `cipher.exe /w:<drive>` is the primary detection anchor. `cipher.exe` is rarely invoked with `/w` outside of deliberate anti-forensic operations. The parent chain (`powershell.exe` → `cmd.exe` → `cipher.exe`) adds context.
- **Sysmon EID 10**: `powershell.exe` holding full access (`0x1FFFFF`) to a long-running `cipher.exe` process is a behavioral indicator of scripted destruction activity — normal users do not access cipher.exe programmatically.
- **Security EID 4689**: `cipher.exe` exit code `0xFFFFFFFF` indicates abnormal termination. A real completed wipe would show `0x0`. Either exit code following an invocation with `/w` is actionable.
- **Behavioral context**: `cipher.exe /w:C:` running as `SYSTEM` from a `cmd.exe` spawned by `powershell.exe` is an unusual privilege level for a legitimate file encryption utility usage pattern — normal EFS usage runs under user accounts, not SYSTEM.
