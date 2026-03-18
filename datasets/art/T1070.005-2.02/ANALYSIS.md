# T1070.005-2: Network Share Connection Removal — Remove Network Share

## Technique Context

T1070.005 (Network Share Connection Removal) covers adversary actions to remove network shares or mapped drive connections to eliminate evidence of lateral movement or data access via SMB. After using a network share to transfer tools, stage data, or move laterally between systems, an attacker may remove that share connection to reduce the evidence of their activity and prevent automated tools from discovering active connections.

This test removes a named network share (`\\test\share`) using the classic `net share <name> /delete` command, executed via `cmd.exe`. The `net.exe` → `net1.exe` invocation chain is characteristic of Windows share management: `net.exe` is a thin wrapper that immediately spawns `net1.exe`, which performs the actual operation. Monitoring for `net.exe` alone without expecting the corresponding `net1.exe` child process is an incomplete detection.

The share targeted (`\\test\share`) is created as a prerequisite by the ART test setup and does not correspond to a real network share in a production environment. In a real attack, this command would target a share that the attacker had previously created or mapped to access resources on the target system.

Both the defended and undefended runs completed successfully. `net share /delete` is standard Windows administration and is not blocked by Defender.

## What This Dataset Contains

The technique execution is well-represented across multiple event types. Security EID 4688 records the full execution chain:
- `"cmd.exe" /c net share \\test\share /delete` — the outer command shell invocation
- `net share \\test\share /delete` — net.exe receiving the subcommand
- `C:\Windows\system32\net1 share \\test\share /delete` — net1.exe performing the actual share removal

All three processes appear with complete command lines showing the target share path `\\test\share /delete`.

Sysmon EID 1 captures the same three processes with process lineage. The `cmd.exe` entry is tagged `technique_id=T1059.003,technique_name=Windows Command Shell`. The `net.exe` and `net1.exe` entries are tagged `technique_id=T1018,technique_name=Remote System Discovery` — a Sysmon rule artifact rather than an accurate technique label (the actual technique is T1070.005, not T1018). The parent chain shows `powershell.exe` (ART orchestration) → `cmd.exe` → `net.exe` → `net1.exe`.

A second `cmd.exe` invocation (`"cmd.exe" /c` with empty body) represents the ART cleanup phase, which was a no-op for this test.

PowerShell script block logging (EID 4104) captures 104 events. The technique content is not in the script block log because the operation was performed via `cmd.exe`, not directly through PowerShell cmdlets. The ART module import is visible.

The dataset contains 130 total events: 104 PowerShell, 6 Security, and 20 Sysmon.

## What This Dataset Does Not Contain

There are no Security audit events specific to share management. Windows does not generate a dedicated event for share deletion in the Security log in the default audit policy configuration — the Security log records only the process launches (EID 4688), not the share operations themselves.

The dataset does not contain SMB-level events, network session events, or events from the SMB service about the share being removed. The Windows Server service does not generate event log entries when a share is deleted via `net share /delete` in typical configurations.

No registry modification events are present. The `net share /delete` command removes the share from the Server service's runtime state but does not directly modify HKLM registry keys in a way that Sysmon would capture as an EID 13 event.

File access events (EID 4663) for any files that were accessible via the deleted share are absent. No direct evidence of what content was accessible through `\\test\share` before deletion is present in this dataset.

## Assessment

The process execution chain for this technique is fully captured and the command line evidence is unambiguous. The three-process chain (`cmd.exe` → `net.exe` → `net1.exe`) with `\\test\share /delete` in the command lines of all three is a strong and complete execution record.

Compared to the defended variant (18 Sysmon, 16 Security, 34 PowerShell), the undefended run has fewer Security events (6 vs. 16) and fewer PowerShell events (104 vs. 34 — wait, the inverse is true here: the undefended run has more PowerShell events at 104 vs. 34, consistent with the ART test framework behavior across this series). The Security event count difference (6 vs. 16) reflects the defended environment accumulating more background 4688 events during the broader test session, not a behavioral difference in the technique itself.

The Sysmon event count is similar (20 vs. 18), consistent with the same process execution profile.

## Detection Opportunities Present in This Data

**`net.exe` / `net1.exe` with `share ... /delete` in command line:** Security EID 4688 and Sysmon EID 1 both capture the full `net share <path> /delete` command. The `/delete` flag combined with a share path is a specific indicator — administrators removing shares for legitimate maintenance purposes would generate the same events, but `net share /delete` executed from a PowerShell-spawned `cmd.exe` under SYSTEM at an unexpected time is anomalous.

**`net.exe` → `net1.exe` child process chain:** Every execution of `net share` spawns `net1.exe` as a child. Sysmon EID 1 captures this lineage. If your detection logic monitors only `net.exe` process creation without extending to `net1.exe` children, you miss half the execution chain. Both processes carry the share path in their command lines.

**`cmd.exe` → `net.exe` spawned from PowerShell:** The parent process chain (`powershell.exe` → `cmd.exe` → `net.exe`) is characteristic of scripted share management. Interactive administrators typically launch `cmd.exe` directly and type `net share` manually — they do not orchestrate it through a PowerShell parent.

**Correlation with prior share creation events:** If your environment logs share creation (e.g., via Group Policy, SIEM rules on `net share <name>=<path>`, or Windows event EID 5142 in the Security log when file/object access auditing is enabled), correlating share creation followed by deletion within a short window can surface share lifecycle anomalies that warrant investigation.
