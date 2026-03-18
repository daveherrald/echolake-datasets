# T1070.005-5: Network Share Connection Removal — Remove Administrative Shares

## Technique Context

T1070.005 Network Share Connection Removal is a defense evasion technique where adversaries remove network shares to limit forensic evidence and reduce their attack surface. Administrative shares (C$, ADMIN$, IPC$) are default Windows shares that provide administrative access to system resources. Removing these shares can hinder incident response efforts by blocking remote administrative tools, preventing lateral movement detection, and obscuring evidence of file access or data exfiltration. The detection community focuses on monitoring `net share` commands with delete operations, unusual share management activity, and the removal of default administrative shares that should typically remain persistent on domain-joined systems.

## What This Dataset Contains

This dataset captures a PowerShell-initiated batch removal of all three default Windows administrative shares using a command loop. The primary execution chain shows PowerShell (PID 43252) spawning cmd.exe with the command `"cmd.exe" /c for %i in (C$ IPC$ ADMIN$) do net share %i /delete`. This cmd.exe process (PID 43988) then iteratively executes three `net.exe` processes, each calling `net1.exe` as the actual implementation:

1. `net share C$ /delete` → `C:\Windows\system32\net1 share C$ /delete`
2. `net share IPC$ /delete` → `C:\Windows\system32\net1 share IPC$ /delete`  
3. `net share ADMIN$ /delete` → `C:\Windows\system32\net1 share ADMIN$ /delete`

Security event logs capture the complete process creation chain with command-line arguments, while Sysmon ProcessCreate events (EID 1) provide additional process metadata and parent-child relationships. All processes execute as NT AUTHORITY\SYSTEM with TokenElevationTypeDefault (1), indicating full administrative privileges. Three WMI Activity events (EID 5858) show `MSFT_SmbShare::FireShareChangeEvent` operations with ResultCode 0x80041007, indicating the actual share modification operations at the SMB provider level.

## What This Dataset Does Not Contain

The dataset lacks evidence of share deletion success or failure, as the `net1.exe` processes exit with status 0x0 but don't generate explicit success/failure telemetry. Windows Defender didn't block this technique since it involves legitimate administrative utilities performing valid (though suspicious) operations. No network-level SMB traffic is captured showing the actual share removal, and there are no System event logs that might contain share deletion notifications. The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`, `Set-StrictMode`) rather than the actual PowerShell commands that initiated the share removal.

## Assessment

This dataset provides excellent telemetry for detecting administrative share removal attacks. The Security channel's 4688 events with command-line logging capture the complete attack chain with high fidelity, while Sysmon ProcessCreate events add valuable process genealogy and hash information. The combination of the batch command structure (`for %i in (C$ IPC$ ADMIN$) do net share %i /delete`) and the systematic net.exe → net1.exe execution pattern creates a distinctive behavioral signature. The WMI Activity events provide additional confirmation of share modification operations at the provider level, though their error codes suggest the shares may not have existed or were already removed.

## Detection Opportunities Present in This Data

1. **Batch Administrative Share Removal Pattern**: Detect cmd.exe processes with command lines containing `for %i in` loops targeting multiple administrative shares (`C$`, `IPC$`, `ADMIN$`) with `/delete` operations.

2. **Sequential net.exe Share Deletion Commands**: Monitor for multiple `net.exe` processes with `share [share_name] /delete` command lines executed in rapid succession, particularly targeting default administrative shares.

3. **PowerShell to CMD Chain for Share Management**: Alert on PowerShell processes spawning cmd.exe with batch commands that iterate through administrative share names for deletion operations.

4. **WMI SMB Share Modification Events**: Correlate WMI Activity EID 5858 events showing `MSFT_SmbShare::FireShareChangeEvent` operations with concurrent net.exe share deletion commands to confirm actual share modifications.

5. **Administrative Share Targeting Pattern**: Create high-confidence alerts when processes attempt to delete all three default administrative shares (C$, IPC$, ADMIN$) within a short time window, as legitimate administration rarely removes all shares simultaneously.
