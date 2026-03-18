# T1069.002-2: Domain Groups — Permission Groups Discovery PowerShell (Domain)

## Technique Context

T1069.002 Domain Groups is a discovery technique where adversaries enumerate domain groups to understand permission structures and identify high-value targets. This is a fundamental reconnaissance activity that helps attackers map out administrative privileges, security group memberships, and potential lateral movement paths within Active Directory environments. The PowerShell cmdlet `Get-ADPrincipalGroupMembership` is a legitimate administrative tool that queries Active Directory to retrieve group memberships for a specified user or computer account, making it attractive to both legitimate administrators and threat actors for domain enumeration activities.

Detection engineers focus on monitoring PowerShell execution of Active Directory cmdlets, especially when executed by unusual processes, from suspicious contexts, or with parameters that suggest reconnaissance behavior. The technique is commonly observed in post-exploitation phases where attackers seek to understand their current privilege level and identify paths to domain administrator access.

## What This Dataset Contains

The dataset captures a clean execution of the `Get-ADPrincipalGroupMembership` PowerShell cmdlet targeting the current user's groups. The key telemetry includes:

**Security Channel (4688/4689 events):** Process creation and termination events showing the PowerShell command line `"powershell.exe" & {get-ADPrincipalGroupMembership $env:USERNAME | select name}` executed by PID 33052, along with a `whoami.exe` execution (PID 17932) and token privilege adjustment (4703).

**PowerShell Channel (4103/4104 events):** PowerShell operational logs capturing the `Set-ExecutionPolicy` cmdlet invocation and script block creation for the AD cmdlet execution. The actual technique command appears in script block ID 83a73c27-980c-4f54-ad22-a3c1f66c685c as `& {get-ADPrincipalGroupMembership $env:USERNAME | select name}`.

**Sysmon Channel:** Process creation events (EID 1) for both `whoami.exe` and the second PowerShell process with the full command line, process access events (EID 10) showing PowerShell accessing the spawned processes, image loads (EID 7) including Active Directory and .NET assemblies, named pipe creation (EID 17), and file creation events (EID 11) for PowerShell profile data.

The execution chain shows the parent PowerShell process (PID 33740) spawning both `whoami.exe` and a child PowerShell process (PID 33052) that executes the AD group enumeration command.

## What This Dataset Does Not Contain

The dataset lacks several important elements that would typically accompany this technique in real-world scenarios. There are no network connection events showing LDAP queries to domain controllers, which would normally be captured as Sysmon EID 3 events when the cmdlet queries Active Directory. The absence suggests either the AD module wasn't fully functional, the domain controller was unreachable, or network logging didn't capture the connections.

The PowerShell channel contains mostly test framework boilerplate (Set-StrictMode, error handling scriptblocks) rather than detailed execution traces of the AD cmdlet itself. There are no events showing the actual results or output of the group enumeration, and no authentication events (like Kerberos ticket requests) that would typically accompany AD queries.

The dataset also lacks any Windows Defender blocking or AMSI (Anti-Malware Scan Interface) events, despite Defender being active, suggesting this legitimate administrative command didn't trigger security controls.

## Assessment

This dataset provides solid process-level telemetry for detecting PowerShell-based domain group enumeration but lacks the network and authentication telemetry that would make detection more comprehensive. The Security and Sysmon channels offer excellent visibility into the command execution, process relationships, and associated system activity. The clear command line capture in both Security 4688 and Sysmon EID 1 events provides strong detection anchors.

However, the missing network telemetry limits the dataset's utility for detecting the actual AD queries that make this technique effective. In production environments, correlating process execution with LDAP connections to domain controllers would significantly strengthen detection capabilities. The dataset is most valuable for organizations focusing on PowerShell command-line monitoring and process behavior analysis.

## Detection Opportunities Present in This Data

1. **PowerShell AD Module Usage**: Monitor for PowerShell processes executing `Get-ADPrincipalGroupMembership` cmdlet in command lines or script blocks, particularly when combined with environment variable references like `$env:USERNAME`.

2. **Suspicious PowerShell Process Chains**: Detect PowerShell processes spawning additional PowerShell instances with AD-related commands, especially when the parent and child processes have different process IDs but related group enumeration activities.

3. **Administrative Discovery Tool Combinations**: Alert on temporal proximity between `whoami.exe` execution and PowerShell AD cmdlets, suggesting systematic user and group discovery activities.

4. **PowerShell Script Block Analysis**: Monitor PowerShell EID 4104 events for script blocks containing Active Directory cmdlets combined with output formatting commands like `select name`, indicating structured reconnaissance.

5. **Process Access Patterns**: Correlate Sysmon EID 10 process access events where PowerShell processes access recently spawned discovery tools, indicating potential automated enumeration frameworks.

6. **Execution Policy Bypass Detection**: Monitor for `Set-ExecutionPolicy` cmdlet usage followed by AD enumeration commands, suggesting attempts to bypass PowerShell security controls for reconnaissance activities.
