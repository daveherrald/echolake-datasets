# T1484.001-1: Group Policy Modification — LockBit Black modify Group Policy settings via cmd

## Technique Context

T1484.001 (Group Policy Modification) covers adversary abuse of Group Policy infrastructure to disable security controls or facilitate domain-wide attack operations. This specific test replicates the LockBit Black ransomware's documented pre-encryption preparation: writing a series of registry keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` to disable Group Policy refresh timing and Windows SmartScreen. When these keys are deployed via GPO, they take effect on every domain machine that processes the policy, making GPO modification a force-multiplier for ransomware deployment at domain scale.

The six registry writes performed in this test directly weaken the target environment:
- `GroupPolicyRefreshTimeDC` = 0 and `GroupPolicyRefreshTimeOffsetDC` = 0 disable the domain controller Group Policy refresh interval
- `GroupPolicyRefreshTime` = 0 and `GroupPolicyRefreshTimeOffset` = 0 disable workstation Group Policy refresh
- `EnableSmartScreen` = 0 disables Windows SmartScreen filtering
- `ShellSmartScreenLevel` = `Block` sets the SmartScreen action level (overridden by the disable above)

The test also executes a cleanup phase that deletes these same keys via `reg delete`. Both phases are captured in this dataset.

## What This Dataset Contains

This dataset captures 17 Security EID 4688 events covering the complete attack sequence — six registry write operations plus six cleanup delete operations plus PowerShell test framework context events — making it the most comprehensive dataset in this batch for process creation coverage.

**Security EID 4688 — attack phase**: PowerShell spawns `cmd.exe` with a compound command using `&` to chain six sequential `reg add` operations:

```
"cmd.exe" /c reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeDC /t REG_DWORD /d 0 /f & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeOffsetDC /t REG_DWORD /d 0 /f & ...
```

Each individual `reg.exe` invocation generates its own EID 4688 event with the full command line. The six attack-phase `reg.exe` events are:
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeDC /t REG_DWORD /d 0 /f`
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeOffsetDC /t REG_DWORD /d 0 /f`
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTime /t REG_DWORD /d 0 /f`
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeOffset /t REG_DWORD /d 0 /f`
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f`
- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f`

All six exit with status `0x0` (success). These keys were written to the registry — the policy modifications took effect on this workstation.

**Security EID 4688 — cleanup phase**: An equivalent compound `reg delete` sequence removes all six keys. The cleanup `reg.exe` invocations are individually captured:
- `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeDC /f`
- `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeOffsetDC /f`
- `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTime /f`
- `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v GroupPolicyRefreshTimeOffset /f`
- (additional cleanup events present for EnableSmartScreen and ShellSmartScreenLevel)

**Sysmon EID 1** captures 17 ProcessCreate events matching the Security log, adding SHA1/MD5/SHA256/IMPHASH hashes for each process. The `reg.exe` invocations are tagged by the sysmon-modular ruleset.

**Sysmon EID 7** (ImageLoad) produces 10 image load events covering DLLs loaded by the PowerShell test framework process. **Sysmon EID 10** captures 4 process access events.

**Sysmon EID 11** records two file creation events: one Defender background scan artifact in `C:\Windows\Temp\` and one PowerShell profile write.

An `MicrosoftEdgeUpdate.exe` EID 4688 event is present — this is background OS activity from the Microsoft Edge auto-update scheduler firing during the test window, not technique-related.

The Application channel (EID 15, 2 events) and PowerShell channel (107 events) are background/test framework activity only.

**Compared to the defended variant** (41 Sysmon / 22 Security / 34 PowerShell): The undefended run has fewer events (34 Sysmon / 17 Security). This is unexpected — the defended run has more events. The likely explanation is that in the defended run, Defender generated additional process creation and access events as it scanned and verified each `reg.exe` invocation. In both runs, all six registry writes completed successfully (Defender does not block `reg.exe` writing to the Group Policy registry path). The difference in event counts reflects Defender's scanning overhead rather than any technique difference.

## What This Dataset Does Not Contain

Registry modification audit events (Security EID 4657) are absent — object access auditing is not enabled in this environment. There is no event confirming that the registry keys were written or read by Group Policy processing. There are no Group Policy operational log events showing the policy taking effect. The dataset captures the command-line evidence of what was written but not any downstream effect of the policy change. System EID 1502/1500 (Group Policy processing) events would confirm policy application but are not included in the collection scope.

## Assessment

This is a high-quality, complete execution dataset for the LockBit Black Group Policy weakening sequence. Every one of the six registry write operations is individually recorded in Security EID 4688 with full command lines, value names, types, and data values. The cleanup phase is also fully captured. All six writes succeeded (`0x0` exit), confirming the policy modifications actually took effect on the registry. Sysmon adds hash verification for each `reg.exe` invocation.

The comprehensiveness of this dataset — 12 individual `reg.exe` events plus compound `cmd.exe` wrappers plus test framework events — makes it well-suited for building behavioral analytics that detect the LockBit Group Policy weakening pattern as a sequence of related `reg.exe` invocations against the same registry path.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `reg.exe add` against `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` with values `GroupPolicyRefreshTime`, `EnableSmartScreen`, or `ShellSmartScreenLevel`. Any modification to the Group Policy refresh interval via registry (bypassing GPMC) is anomalous.
- **Security EID 4688**: The compound `cmd.exe` command line containing multiple sequential `reg add` operations against the same Group Policy path is the LockBit Black signature. The specific value names are documented in threat intelligence reporting on LockBit 3.0.
- **Security EID 4688**: `reg.exe add ... /v EnableSmartScreen /t REG_DWORD /d 0` — disabling SmartScreen via registry in a batch operation is a strong ransomware pre-deployment indicator.
- **Sysmon EID 1**: Multiple `reg.exe` invocations in rapid succession with identical parent `cmd.exe` and the `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` path — the timing and volume of `reg.exe` spawns from a single `cmd.exe` is a behavioral cluster.
- **Behavioral sequence**: Six `reg add` operations followed by six `reg delete` operations against the same key set is the ART cleanup pattern. In a real attack, only the `add` phase would occur. Detecting the `add` phase alone, without the subsequent cleanup, is the meaningful detection.
