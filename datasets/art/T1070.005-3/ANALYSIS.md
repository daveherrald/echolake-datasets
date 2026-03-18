# T1070.005-3: Network Share Connection Removal — Remove Network Share PowerShell

## Technique Context

T1070.005 - Network Share Connection Removal is a defense evasion technique where adversaries remove connections to network shares that were created during their operations to hide evidence of their activities. This technique is commonly used by attackers after lateral movement or data collection activities to clean up artifacts that could indicate their presence on compromised systems. The detection community focuses on monitoring share removal commands, unusual PowerShell cmdlets targeting SMB shares, and administrative activities that could indicate cleanup operations. Network share removal can be accomplished through various methods including PowerShell cmdlets, net commands, or direct registry manipulation.

## What This Dataset Contains

This dataset captures the execution of PowerShell cmdlets attempting to remove network shares that don't exist. The key evidence is found in the Security event 4688 showing the PowerShell command line:

`"powershell.exe" & {Remove-SmbShare -Name \\test\share\nRemove-FileShare -Name \\test\share}`

The PowerShell operational events show detailed execution traces including CommandInvocation events (EID 4103) for both `Remove-SmbShare` and `Remove-FileShare` cmdlets with parameter bindings showing the target share name "\\test\share". Both commands generate NonTerminatingError messages indicating "No MSFT_SMBShare objects found" and "No MSFT_FileShare objects found" respectively, demonstrating the attempted removal of non-existent shares.

Sysmon captures the full process chain starting with the parent PowerShell process (PID 39840) spawning the child PowerShell process (PID 40332) that executes the share removal commands. The dataset includes comprehensive DLL loading events showing the PowerShell execution environment initialization, including System.Management.Automation.ni.dll loads that indicate PowerShell cmdlet execution.

## What This Dataset Does Not Contain

This dataset does not contain evidence of actual successful share removal since the target shares didn't exist. There are no network-related Sysmon events (EID 3) showing actual SMB connections being terminated. The dataset lacks any registry modification events that would typically accompany successful share removal operations. There are no file system changes related to share configuration files or logs that would be modified during actual share removal. The technique execution completed without triggering Windows Defender blocks, so there's no evidence of endpoint protection intervention.

## Assessment

This dataset provides moderate value for detection engineering, primarily demonstrating the telemetry patterns for attempted network share removal operations. The PowerShell operational logs are particularly valuable, capturing both the command invocation patterns and the specific error conditions when shares don't exist. The Security 4688 events with command-line logging provide clear evidence of the technique attempt. However, the dataset's limitation is that it only shows failed removal attempts rather than successful operations, which limits its utility for understanding the full technique lifecycle. The comprehensive process creation and DLL loading telemetry in Sysmon provides good context for the PowerShell execution environment.

## Detection Opportunities Present in This Data

1. Monitor Security EID 4688 events for PowerShell command lines containing "Remove-SmbShare" or "Remove-FileShare" cmdlets with UNC path parameters
2. Alert on PowerShell EID 4103 CommandInvocation events specifically targeting Remove-SmbShare and Remove-FileShare functions
3. Detect PowerShell script block execution (EID 4104) containing share removal cmdlets in combination with error handling or cleanup operations
4. Monitor for PowerShell processes loading SMB-related modules (SmbShare, Storage) as indicated by module import activities
5. Create behavioral analytics for PowerShell sessions executing multiple share-related cmdlets in sequence, particularly removal operations
6. Track PowerShell parameter binding events showing UNC paths being passed to removal cmdlets as potential cleanup indicators
7. Monitor for PowerShell NonTerminatingError patterns related to share objects not being found, which could indicate failed cleanup attempts
