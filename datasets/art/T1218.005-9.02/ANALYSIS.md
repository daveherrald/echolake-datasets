# T1218.005-9: Mshta — Invoke HTML Application - Simulate Lateral Movement over UNC Path

## Technique Context

T1218.005 (Mshta) encompasses adversary abuse of `mshta.exe` to execute HTML Applications. This specific test variant simulates a lateral movement scenario where an `.hta` payload is delivered via a UNC path rather than a direct local file path or inline protocol handler. In real intrusions, attackers stage `.hta` files on SMB shares or on attacker-controlled infrastructure, then deliver them to victim machines using a path like `\\attacker\share\payload.hta`. This test generates a local UNC path to simulate this pattern without requiring a remote server.

The UNC path delivery pattern is significant for detection because it suggests the HTA file originates from network storage rather than local disk, which is unusual for legitimate `mshta.exe` usage. Defenders monitor for `mshta.exe` command lines referencing UNC paths (`\\`), unexpected process lineage, and child processes spawned from `mshta.exe` in this context.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset spans 2026-03-17T16:56:25Z to 2026-03-17T16:56:27Z and contains 157 total events: 115 PowerShell, 4 Security, and 38 Sysmon.

**Security EID 4688 records the test invocation:**

```
"powershell.exe" & {Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath -MSHTAFilePath $env:windir\system32\mshta.exe}
```

The `-TemplatePE` flag instructs the ATH framework to embed a PE payload template in the HTA, and `-AsLocalUNCPath` causes it to create and reference a local UNC path (`\\127.0.0.1\...` or `\\localhost\...` style) to simulate the lateral movement delivery vector.

**Sysmon EID 1** captures 4 process creation events. A child PowerShell process with the full `Invoke-ATHHTMLApplication` command line appears:

```
"powershell.exe" & {Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath -MSHTAFilePath $env:windir\system32\mshta.exe}
```

Tagged with `technique_id=T1083` (File and Directory Discovery) by sysmon-modular rules. Two `whoami.exe` executions appear, confirming the payload ran.

**Sysmon EID 7 (Image Load)** produces 25 events documenting .NET runtime DLL loading in both PowerShell processes (`mscoree.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, `MpOAV.dll`, `MpClient.dll`, `urlmon.dll`).

**Sysmon EID 10 (Process Access)** records 4 events: PowerShell accessing the child PowerShell process and `whoami.exe` with `GrantedAccess: 0x1fffff`.

**Sysmon EID 17 (Pipe Created)** records 3 events for PowerShell host communication pipes in both processes.

**Sysmon EID 11 (File Created)** records 2 events for PowerShell profile files (`StartupProfileData-NonInteractive`, `StartupProfileData-Interactive`). No HTA file creation events appear here despite the test being designed to create a local UNC-path HTA — this is consistent with the ATH framework's file writing happening in a path not covered by Sysmon's EID 11 include rules, or the file write occurring in a monitored but excluded temp directory.

**PowerShell EID 4104** produces 112 EID 4104 events and 3 EID 4103 events. The EID 4103 events represent PowerShell module logging for cmdlet invocations. The 4104 events are primarily test framework boilerplate.

**Security EID 4688** records 4 events: the two `whoami.exe` executions, the child PowerShell with the ATH command, and a cleanup command.

## What This Dataset Does Not Contain

No `mshta.exe` process creation events appear anywhere in this dataset. As with T1218.005-7 and T1218.005-8, this is a Sysmon include-mode coverage gap for ProcessCreate. The two `whoami.exe` events confirm the technique succeeded — the ATH framework only executes `whoami.exe` after the HTA payload runs.

No file creation events show the HTA file itself being written. The ATH framework's `-TemplatePE -AsLocalUNCPath` approach creates a temporary file in a location that Sysmon's EID 11 rules may not cover, or the file is created and deleted within the same brief window.

No network events (Sysmon EID 3) appear showing SMB connections to the local UNC path. This is expected — SMB loopback connections are typically not captured by the network connection filter in this Sysmon configuration, and the local UNC path doesn't require a real network hop.

No registry events capture any COM or file association registration that might accompany HTA execution.

## Assessment

This dataset documents a successful undefended Mshta execution via UNC path delivery, with Defender absent. The core technique executed (confirmed by `whoami.exe` payload runs), and the invocation command line is preserved in Security EID 4688. The absence of `mshta.exe` from process creation telemetry is a Sysmon configuration limitation rather than a technique failure.

Compared to the defended variant (36 Sysmon, 12 Security, 45 PowerShell), this undefended run produced more PowerShell events (115 vs. 45) and slightly more Sysmon events (38 vs. 36), with the additional PowerShell EID 4103 module logging events reflecting the more active PowerShell execution environment.

## Detection Opportunities Present in This Data

**Security EID 4688:** The command line `"powershell.exe" & {Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath -MSHTAFilePath $env:windir\system32\mshta.exe}` is explicitly adversarial. Any process creation event with `Invoke-ATHHTMLApplication` in the command line is a direct indicator of ATH-based testing. In a real intrusion, the equivalent would be a PowerShell process spawning `mshta.exe` with a UNC path argument — look for `mshta.exe` with `\\` in its command line.

**Sysmon EID 1:** The child PowerShell process is captured with full parent/child relationship detail and tagged by sysmon-modular rules. The `whoami.exe` executions with `powershell.exe` as parent add supporting behavioral evidence.

**Sysmon EID 10:** Full-access process access from PowerShell to the child PowerShell (`GrantedAccess: 0x1fffff`) is present. Combined with the Security 4688 invocation, this cross-correlates to identify the suspicious process chain.

**PowerShell EID 4103 (Module Logging):** Three module logging events appear in this dataset (vs. 1 in the T1218.005-7 run), suggesting more active PowerShell invocation around the UNC path handling. Module logging capturing cmdlet invocations can add context to what functions the test framework called during the test.
