# T1490-2: Inhibit System Recovery — Delete Volume Shadow Copies via WMI

## Technique Context

T1490 (Inhibit System Recovery) via WMI covers the most well-documented ransomware pre-encryption step: deleting Volume Shadow Copies using `wmic.exe shadowcopy delete`. This command invokes the Windows Management Instrumentation API to enumerate and delete all VSS snapshots in a single operation. The technique has appeared in documented ransomware families including Ryuk, Conti, LockBit, BlackCat/ALPHV, and many others. Detection engineering teams treat any VSC deletion as a high-confidence ransomware indicator because legitimate administrative scripts almost never touch shadow copies in this manner.

`wmic.exe shadowcopy delete` is the canonical form; no target path, no qualifiers, just a blanket deletion of all shadow copies on the system. This runs in the SYSTEM context in this test, which has access to VSS provider APIs.

## What This Dataset Contains

This dataset captures a clean, complete execution of VSC deletion via WMI on ACME-WS06 with Defender disabled.

**Security EID 4688** records the complete process chain. PowerShell (running as `NT AUTHORITY\SYSTEM`, creator SID `S-1-5-18`, logon ID `0x3E7`) spawns:

```
"cmd.exe" /c wmic.exe shadowcopy delete
```

`cmd.exe` in turn spawns:

```
wmic.exe shadowcopy delete
```

Both process creation events are captured with full command lines and the SYSTEM creator subject.

Additionally, Security EID 4688 records the Volume Shadow Copy Service itself (`vssvc.exe`) being started by `services.exe` during this operation, as the VSS service activates to handle the deletion request. A `dllhost.exe` process is also spawned by `services.exe` with the CLSID `{293A8973-74FD-4DB4-A4D7-4F33C49DFEBE}`, which is the VSS COM server that handles WMI-initiated VSS operations.

**Security EID 4799** (8 events): Security-enabled local group membership was enumerated, specifically checking the `Administrators` (S-1-5-32-544) and `Backup Operators` (S-1-5-32-551) groups by a process running as SYSTEM. Eight events means the enumeration occurred four times (Administrators + Backup Operators, repeated). This is the VSS provider checking backup operator permissions before deleting shadow copies — a normal artifact of the VSS deletion workflow that only appears when the deletion actually succeeds. These EID 4799 events are a secondary confirmation that the deletion ran.

**Security EID 4624 and 4672**: Network logon and special privilege assignment events, background infrastructure for the SYSTEM context.

**Sysmon EID 1** captures the `cmd.exe`, `wmic.exe`, and a second empty `cmd.exe` cleanup invocation with full hashes. The sysmon-modular rules tag both the `cmd.exe` event (`technique_id=T1059.003`) and the `wmic.exe` event (`technique_id=T1490,technique_name=Inhibit System Recovery`) — the VSC deletion rule fires correctly on `wmic.exe shadowcopy delete`.

**Sysmon EID 3** (NetworkConnect): Two events show `MsMpEng.exe` (Defender, running as a background service even with real-time protection disabled) connecting to `48.211.72.139:443`. This is Defender's telemetry submission infrastructure — background noise, not technique-related. The same IP appears in T1486-9.

**Sysmon EID 7** (ImageLoad): 16 DLL load events document the PowerShell assembly stack. **Sysmon EID 17** captures the PowerShell named pipe. **Sysmon EID 11** records the PowerShell profile write.

The PowerShell channel (107 events) is test framework boilerplate. The WMI channel is not included in the bundled files despite a WMI event being referenced in the provenance — see below.

**Compared to the defended variant** (30 Sysmon / 13 Security / 34 PowerShell): The undefended run has slightly fewer Sysmon events (29 vs. 30) but significantly more Security events (20 vs. 13). The higher Security count in the undefended run is driven by the 8 EID 4799 events from the VSS deletion workflow and the `vssvc.exe` / `dllhost.exe` process creations that only appear when the deletion actually runs — these are absent from the defended run where Defender blocked the execution. This is the clearest structural difference between defended and undefended for this technique.

## What This Dataset Does Not Contain

The `Microsoft-Windows-WMI-Activity/Operational` channel is not included in the bundled dataset files, even though the provenance notes a WMI event was observed in the source collection. If included, this channel would provide `WMI-Activity EID 5861` events showing the WMI query that executed the shadow copy deletion through the `root\cimv2` namespace. The VSS Application log confirming which shadow copies existed before deletion is also absent. The System channel, which would contain EID 7036 for the VSS service state changes (`vssvc.exe` stopping and starting), is not bundled.

`WmiPrvSE.exe` (the WMI Provider Host that executes the actual deletion) does not appear as a Sysmon EID 1 event because it is not in the sysmon-modular include-mode process creation filter.

## Assessment

This is a strong, clean dataset for the `wmic.exe shadowcopy delete` pattern. The command chain is fully captured in Security EID 4688 and Sysmon EID 1, both with `0x0` exit codes confirming successful deletion. The 8 EID 4799 group membership enumeration events from the VSS deletion workflow are a distinctive secondary artifact that only appears in successful deletion runs — they are absent from the defended dataset where Defender blocked execution. The `vssvc.exe` and VSS COM server `dllhost.exe` process creations in Security EID 4688 are additional confirmation artifacts.

The Sysmon rule tagging (`T1490,technique_name=Inhibit System Recovery`) on the `wmic.exe` event demonstrates correct behavioral identification by the ruleset.

## Detection Opportunities Present in This Data

- **Sysmon EID 1**: `wmic.exe shadowcopy delete` tagged `technique_id=T1490,technique_name=Inhibit System Recovery`. The rule already fires; the command line is the detection anchor.
- **Security EID 4688**: `wmic.exe shadowcopy delete` spawned by `cmd.exe` spawned by `powershell.exe` running as SYSTEM. The full process chain is present with creator SID `S-1-5-18`.
- **Security EID 4688**: `vssvc.exe` started by `services.exe` during a session where `wmic.exe shadowcopy delete` was invoked — the VSS service activation as a consequence of the WMI deletion call correlates the service startup to the attack operation.
- **Security EID 4799**: Repeated enumeration of `Administrators` and `Backup Operators` group membership by a SYSTEM process immediately following a `wmic.exe shadowcopy delete` invocation. This four-pair EID 4799 burst is a distinctive secondary artifact of successful VSC deletion via WMI.
- **Security EID 4689**: `wmic.exe` exit code `0x0` following a `shadowcopy delete` invocation confirms completion. The defended variant's exit code (`0xC0000022`) would appear instead if Defender had intervened.
- **Sysmon EID 3**: Defender telemetry connections to `48.211.72.139:443` from `MsMpEng.exe` are background noise and should not be attributed to the technique.
