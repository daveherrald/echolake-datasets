# T1070.005-3: Network Share Connection Removal — Remove Network Share PowerShell

## Technique Context

T1070.005 (Network Share Connection Removal) covers the removal of network shares or mapped connections to reduce forensic evidence after lateral movement or data operations. This test uses the PowerShell SMB cmdlets `Remove-SmbShare` and `Remove-FileShare` to remove the share `\\test\share`, rather than the `net.exe` command-line approach used in T1070.005-2.

The difference between the `net share /delete` approach and the PowerShell SMB cmdlets is more than syntactic. `Remove-SmbShare` is part of the `SmbShare` PowerShell module (introduced in Windows Server 2012 / Windows 8), which interfaces with the SMB stack directly via CIM/WMI rather than spawning `net.exe` and `net1.exe`. This means the process creation telemetry is different: instead of a three-process chain visible in Security EID 4688, you see a single PowerShell process with the share cmdlet in its command line.

`Remove-FileShare` is an alias or variant for removing a share via the `Storage` module, providing a second attempt to remove the same target if `Remove-SmbShare` fails or is not available. In practice, both cmdlets target the same underlying Windows SMB API.

Both the defended and undefended runs completed without interference from endpoint controls.

## What This Dataset Contains

The primary technique evidence is Security EID 4688 recording the PowerShell process launch with command line: `"powershell.exe" & {Remove-SmbShare -Name \\test\share Remove-FileShare -Name \\test\share}`. Both cmdlets appear in the same command block. The parent process is the ART orchestration `powershell.exe`.

Sysmon EID 1 captures the same PowerShell launch with the same command line, tagged `technique_id=T1059.001,technique_name=PowerShell`. The full command block is visible including both `Remove-SmbShare` and `Remove-FileShare` invocations.

Security EID 4688 also records `WmiApSrv.exe` (`C:\Windows\system32\wbem\WmiApSrv.exe`) being launched. This is the WMI Adapter service activating in response to the SMB module's CIM/WMI calls — an indicator that `Remove-SmbShare` uses the WMI infrastructure to execute. The WmiApSrv.exe launch distinguishes this PowerShell-based approach from the `net.exe`-based T1070.005-2 method.

The ART cleanup EID 4688 and Sysmon EID 1 entries record the cleanup script block (`Invoke-AtomicTest T1070.005 -TestNumbers 3 -Cleanup -Confirm:$false`).

PowerShell script block logging (EID 4104) captures 125 events. The ART cleanup script block is visible as a standalone entry. The technique payload itself appears in the Sysmon EID 1 / Security EID 4688 command line rather than as an isolated 4104 block.

Sysmon EID 10 records process access events for PowerShell, and EID 7 records image loads. The dataset spans a slightly longer window than the `net.exe` variant, reflecting the WMI service activation overhead. Total events: 125 PowerShell, 7 Security, 39 Sysmon.

## What This Dataset Does Not Contain

No WMI operational events (e.g., Microsoft-Windows-WMI-Activity/Operational EID 5861) are present in this dataset. While `WmiApSrv.exe` is recorded launching in the Security log, the WMI operational channel was not collected here. In contrast, the T1070.005-5 dataset (which also uses WMI-backed share operations) includes WMI EID 5858 events.

There are no SMB-level events, Security log events for share operations (EID 5142 for share delete in Security log under Object Access auditing), or network events.

The dataset does not record what shares existed before or after the operation. If `\\test\share` did not exist when the cmdlets ran, the cmdlets would produce an error rather than a successful removal — but error handling is not explicitly captured in the available event fields.

No Defender events, registry modifications (the SMB module does not write registry keys when removing a share), or file system artifacts are present.

## Assessment

The PowerShell-based share removal via SMB cmdlets is captured with high fidelity. The command line in Sysmon EID 1 and Security EID 4688 shows both `Remove-SmbShare` and `Remove-FileShare` targeting `\\test\share`. The WmiApSrv.exe launch is a useful secondary indicator that distinguishes this execution method from the direct `net.exe` approach.

Compared to the defended variant (33 Sysmon, 12 Security, 67 PowerShell), the undefended dataset has more total events (39 Sysmon, 7 Security, 125 PowerShell). The higher event counts in the undefended run are consistent with the broader ART test framework behavior. The Security event count difference (7 vs. 12) and Sysmon difference (39 vs. 33) are small enough to reflect normal variability rather than any meaningful behavioral distinction.

The key behavioral difference versus T1070.005-2 is the absence of a `net.exe`/`net1.exe` process chain. Any detection logic specific to `net share /delete` command syntax would miss this PowerShell variant. This dataset provides a useful complement to T1070.005-2 for validating that coverage extends to the PowerShell SMB module approach.

## Detection Opportunities Present in This Data

**`Remove-SmbShare` or `Remove-FileShare` in PowerShell command line:** Security EID 4688 and Sysmon EID 1 both capture the complete PowerShell block. String matching on `Remove-SmbShare` or `Remove-FileShare` in process command lines is a high-fidelity detection anchor — these cmdlets have limited legitimate use in most enterprise environments outside of provisioning scripts, and legitimate scripts would not typically execute under SYSTEM context as an inline one-liner.

**WmiApSrv.exe launched from PowerShell SMB operation:** The WMI Adapter service (`WmiApSrv.exe`) launching in the context of a PowerShell session that also contains `Remove-SmbShare` is a corroborating signal. On its own, WmiApSrv.exe launching is not suspicious, but combined with the PowerShell command line context it helps confirm that WMI-backed share management occurred.

**PowerShell parent spawning PowerShell for share removal:** The process tree (`powershell.exe` → `powershell.exe` with `Remove-SmbShare`) is visible in Sysmon EID 1. PowerShell-to-PowerShell chaining for share removal under SYSTEM is not characteristic of legitimate administrative workflows.

**Absence of `net.exe`/`net1.exe` in complement to share removal activity:** If you see share-related evidence elsewhere (e.g., in SMB session logs or prior EID 5140/5142 events) but no `net.exe` process creation, the PowerShell SMB module approach should be considered as an alternative execution path.
