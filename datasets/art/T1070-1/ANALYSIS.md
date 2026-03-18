# T1070-1: Indicator Removal — Indicator Removal using FSUtil

## Technique Context

T1070 Indicator Removal encompasses adversary techniques to delete or modify artifacts generated during their operation to avoid detection. Subtest T1070.001 specifically focuses on using the FSUtil utility to delete the NTFS Change Journal (USN Journal), which records detailed information about file system changes including file creation, deletion, modification, and renaming operations. This technique is particularly valuable to adversaries because the USN Journal is a rich source of forensic evidence that incident responders and threat hunters use to reconstruct attack timelines and identify compromised files.

The FSUtil utility is a legitimate Windows administrative tool, making its use for malicious purposes a classic example of "living off the land" techniques. The command `fsutil usn deletejournal /D C:` completely deletes the USN Journal for the C: drive, effectively erasing a critical forensic artifact. Detection engineers focus on monitoring FSUtil executions with USN-related parameters, as legitimate administrative use of this specific functionality is relatively rare in most environments.

## What This Dataset Contains

This dataset captures a successful execution of the FSUtil USN Journal deletion technique with comprehensive telemetry across multiple event sources. The attack flow shows PowerShell invoking cmd.exe, which then executes `fsutil usn deletejournal /D C:`. 

Key telemetry captured includes:

- **Process execution chain**: Security EID 4688 events show PowerShell (PID 13900) → cmd.exe (PID 14840, command line `"cmd.exe" /c fsutil usn deletejournal /D C:`) → fsutil.exe (PID 16172, command line `fsutil usn deletejournal /D C:`)
- **Sysmon process creation**: EID 1 events with full command lines and process relationships, including the critical fsutil execution with RuleName `technique_id=T1070,technique_name=Indicator Removal`
- **Process access events**: Sysmon EID 10 showing PowerShell accessing both the cmd.exe and whoami.exe processes with full access rights (0x1FFFFF)
- **Process termination**: Security EID 4689 events showing clean exits (status 0x0) for all processes
- **Privilege adjustment**: Security EID 4703 showing PowerShell enabling multiple high-privilege rights including SeBackupPrivilege and SeManageVolumePrivilege

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual technique execution commands.

## What This Dataset Does Not Contain

This dataset lacks several elements that would provide additional detection opportunities:

- **File system audit events**: No Security EID 4663 events showing the actual USN Journal file deletion, likely because object access auditing is disabled per the configuration
- **Sysmon file deletion events**: No EID 23 events for the USN Journal file deletion, which would provide direct evidence of the artifact removal
- **Registry modifications**: FSUtil operations may involve registry access that isn't captured here
- **Network activity**: No network-related events, though this technique is purely local
- **Additional PowerShell script block content**: The technique execution doesn't appear in PowerShell script block logging, suggesting it was invoked through a simpler mechanism

The absence of object access auditing significantly limits visibility into the actual file system changes that constitute the technique's primary impact.

## Assessment

This dataset provides excellent process-level telemetry for detecting FSUtil-based USN Journal deletion. The Security and Sysmon channels together capture the complete process execution chain with full command lines, making detection straightforward. The Sysmon EID 1 event for fsutil.exe execution includes the technique-specific RuleName, demonstrating that existing detection rules can effectively identify this activity.

However, the dataset's detection value is somewhat limited by the lack of file system audit events. While process execution is clearly visible, the actual deletion of the USN Journal file—the technique's ultimate objective—isn't directly captured. This means detections would rely on command line analysis rather than observing the actual file system impact.

The privilege escalation telemetry (EID 4703) adds valuable context, showing PowerShell acquiring privileges necessary for low-level disk operations. The clean process exit codes indicate the technique executed successfully without errors.

## Detection Opportunities Present in This Data

1. **FSUtil USN Journal deletion command line detection**: Monitor Security EID 4688 or Sysmon EID 1 for fsutil.exe processes with command lines containing "usn deletejournal", particularly with the /D parameter targeting system drives.

2. **PowerShell-initiated FSUtil execution**: Detect process chains where PowerShell spawns cmd.exe which then executes fsutil.exe with USN-related parameters, indicating potential scripted artifact removal.

3. **High-privilege FSUtil execution**: Alert on fsutil.exe execution by processes that have recently acquired SeBackupPrivilege or SeManageVolumePrivilege (Security EID 4703 followed by fsutil execution).

4. **Process access patterns**: Monitor Sysmon EID 10 events showing PowerShell accessing cmd.exe processes with full rights (0x1FFFFF) followed immediately by fsutil execution.

5. **Anomalous FSUtil usage**: Baseline normal FSUtil command patterns in the environment and alert on the rare "usn deletejournal" subcommand, as legitimate use is uncommon in most enterprise environments.

6. **Parent-child process relationship detection**: Alert on cmd.exe processes spawned by PowerShell that subsequently launch fsutil.exe, particularly with system-level privileges and USN-related parameters.
