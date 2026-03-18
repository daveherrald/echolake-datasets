# T1136.002-3: Domain Account — Create a new Domain Account using PowerShell

## Technique Context

T1136.002 focuses on adversaries creating new domain accounts to establish persistence and expand their access within Active Directory environments. This technique is particularly valuable for attackers who have gained initial access but need to create additional accounts for long-term access, lateral movement, or backup access methods. The detection community prioritizes monitoring for unusual account creation patterns, especially when performed via PowerShell APIs rather than standard administrative tools. Domain account creation requires elevated privileges and generates multiple event types across different log sources, making it a high-confidence detection target when properly instrumented.

## What This Dataset Contains

This dataset captures a PowerShell-based domain account creation attempt using the .NET System.DirectoryServices.AccountManagement namespace. The Security channel shows the complete PowerShell command line in EID 4688: `"powershell.exe" & {$SamAccountName = 'T1136.002_Admin' ... $User.Save() $User}` with the full account creation script visible. The PowerShell operational logs contain detailed script block logging (EID 4104) showing the complete technique implementation, including `ConvertTo-SecureString 'T1136_pass123!' -AsPlainText -Force` and `Add-Type -AssemblyName System.DirectoryServices.AccountManagement`. Command invocation events (EID 4103) capture individual cmdlet executions like `New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal`. Sysmon provides process creation events for both the parent PowerShell session and the child PowerShell process executing the account creation script (EID 1), plus extensive DLL loading events showing .NET framework initialization and Windows Defender interaction.

## What This Dataset Does Not Contain

The dataset lacks the actual Active Directory account creation events that would appear in the Domain Controller's Security log (EID 4720 - A user account was created). Since this test runs on a domain workstation rather than a domain controller, we don't see the authoritative account creation events or any associated group membership changes (EID 4728/4732). The dataset also doesn't contain network authentication events that would show the workstation authenticating to the domain controller to perform the account creation. Windows Defender appears to have allowed the technique to execute (no blocking events), but we don't see definitive success telemetry confirming the account was actually created in Active Directory.

## Assessment

This dataset provides excellent visibility into PowerShell-based domain account creation attempts from an endpoint perspective. The combination of Security 4688 events with full command-line logging and PowerShell's comprehensive script block logging creates multiple high-fidelity detection opportunities. The technique artifacts are clearly visible across multiple data sources, with the plaintext password and suspicious account naming pattern ('T1136.002_Admin') making this particularly detectable. However, the dataset's primary limitation is the lack of domain controller telemetry to confirm whether the account creation actually succeeded. For complete detection coverage of this technique, organizations need both endpoint telemetry (captured here) and domain controller logging.

## Detection Opportunities Present in This Data

1. PowerShell script block logging (EID 4104) containing `System.DirectoryServices.AccountManagement` namespace usage with account creation methods like `UserPrincipal` and `.Save()`
2. Command-line arguments in Security EID 4688 showing PowerShell execution with embedded domain account creation scripts
3. PowerShell command invocation events (EID 4103) for suspicious cmdlet combinations: `ConvertTo-SecureString` with `-AsPlainText -Force` followed by `Add-Type` loading directory services assemblies
4. Process creation patterns showing PowerShell spawning child PowerShell processes with account creation command lines
5. Sysmon EID 7 events showing loading of System.DirectoryServices.AccountManagement.dll or related .NET assemblies in PowerShell processes
6. Hardcoded password strings in PowerShell script blocks (`T1136_pass123!`) indicating programmatic account creation rather than interactive administration
7. Suspicious account naming patterns (`T1136.002_Admin`) in script block content suggesting automated or test account creation
8. PowerShell named pipe creation (EID 17) followed by .NET directory services API usage indicating programmatic domain interaction
