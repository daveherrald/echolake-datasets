# T1003.003-5: NTDS — Create Volume Shadow Copy remotely with WMI

## Technique Context

T1003.003 (NTDS) focuses on extracting credential data from the Windows domain controller's NTDS.dit file, which contains the Active Directory database including password hashes for all domain accounts. While the traditional NTDS technique targets domain controllers directly, this specific test demonstrates using Volume Shadow Copy Service (VSS) via WMI to create shadow copies that could facilitate credential access. VSS creates point-in-time snapshots of volumes, allowing attackers to access locked files like NTDS.dit or SAM databases that are normally in use by the system. The detection community focuses on VSS creation activity, WMI usage patterns, privilege escalation events, and subsequent file access patterns that indicate credential harvesting attempts.

## What This Dataset Contains

This dataset captures a WMI-based volume shadow copy creation attempt executed via PowerShell. The core technique manifests through Security event 4688 showing the process chain: `powershell.exe` → `cmd.exe /c wmic /node:"localhost" shadowcopy call create Volume=C:\` → `wmic.exe /node:"localhost" shadowcopy call create Volume=C:\`. Sysmon captures the WMIC process creation with EID 1 but the initial PowerShell processes don't appear in Sysmon ProcessCreate due to the include-mode filtering configuration.

The Volume Shadow Copy Service activity generates extensive registry telemetry through Sysmon EID 13 events from `vssvc.exe` (PID 7080) and `svchost.exe` (PID 6736), showing VSS diagnostic entries like `HKLM\System\CurrentControlSet\Services\VSS\Diag\SwProvider_{...}\PROVIDER_BEGINPREPARE` and volume-specific operations on `Volume{6e20c311-c974-475c-b1c6-c5882a662d13}`. Security events show privilege token adjustments (EID 4703) for both PowerShell and WMIC processes, indicating elevated permissions required for VSS operations including `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeManageVolumePrivilege`.

## What This Dataset Does Not Contain

The dataset lacks evidence of actual NTDS.dit or credential file access following the shadow copy creation. While VSS registry activity indicates the shadow copy was created, there are no file access events showing enumeration or copying of credential databases from the shadow volume. The PowerShell script block logging contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`) rather than the actual shadow copy creation commands. Additionally, the sysmon-modular configuration's include-mode filtering for ProcessCreate means the initial PowerShell execution that likely contained the technique implementation isn't captured in Sysmon EID 1 events.

## Assessment

This dataset provides good coverage of the VSS creation mechanics through WMI but represents an incomplete implementation of the full NTDS technique. The Security channel's process creation events with command-line logging effectively capture the WMI usage pattern, while Sysmon's extensive registry monitoring reveals the internal VSS operations. However, the lack of subsequent credential access activity limits its utility for detecting complete NTDS attacks. The privilege escalation events (EID 4703) are particularly valuable as they show the specific privileges required for VSS operations. For detection engineering, this data is most useful for building alerts around WMI-based VSS creation patterns rather than end-to-end credential theft scenarios.

## Detection Opportunities Present in This Data

1. **WMI Shadow Copy Creation via Command Line**: Security EID 4688 process creation showing `wmic.exe` with command line containing "shadowcopy call create" parameters, particularly with localhost targeting

2. **PowerShell-Initiated WMI Process Chain**: Process creation sequence from PowerShell spawning cmd.exe which then executes WMIC with shadow copy operations

3. **VSS Registry Activity Correlation**: Multiple Sysmon EID 13 registry events from vssvc.exe writing to VSS diagnostic registry keys, indicating active volume shadow copy operations

4. **Privilege Token Adjustment for VSS**: Security EID 4703 events showing PowerShell and WMIC processes enabling critical privileges like SeBackupPrivilege, SeRestorePrivilege, and SeManageVolumePrivilege

5. **WMI Service Process Activity**: Sysmon EID 7 showing WmiApSrv.exe loading suspicious DLLs including AMSI integration, indicating WMI service activation for shadow copy operations

6. **Volume-Specific VSS Operations**: Registry writes containing specific volume GUIDs in VSS diagnostic paths, allowing correlation of shadow copy activity to specific drives or partitions
