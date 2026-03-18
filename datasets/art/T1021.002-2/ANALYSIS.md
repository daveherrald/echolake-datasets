# T1021.002-2: SMB/Windows Admin Shares — Map Admin Share PowerShell

## Technique Context

T1021.002 (SMB/Windows Admin Shares) represents a fundamental lateral movement technique where attackers leverage administrative shares (C$, ADMIN$, etc.) and SMB protocols to access remote systems. This technique is particularly significant because it uses legitimate Windows functionality that's commonly enabled in enterprise environments. Attackers typically use this technique after obtaining administrative credentials through techniques like credential dumping or pass-the-hash attacks.

The detection community focuses heavily on this technique because it's both high-value for attackers (enabling broad lateral movement) and generates distinctive telemetry. Key detection points include UNC path access patterns, administrative share enumeration, and PowerShell cmdlets like `New-PSDrive` that map network drives. This technique often appears in APT campaigns and is a cornerstone of post-exploitation activity.

## What This Dataset Contains

This dataset captures a PowerShell-based admin share mapping attempt using the command `New-PSDrive -name g -psprovider filesystem -root \\Target\C$`. The technique execution is comprehensively logged across multiple channels:

**Security Channel Events (17 events):**
- Process creation for PowerShell execution with command line: `"powershell.exe" & {New-PSDrive -name g -psprovider filesystem -root \\Target\C$}`
- Multiple privilege escalation events (EID 4703) showing SYSTEM token adjustments with elevated privileges including SeBackupPrivilege and SeRestorePrivilege
- Process termination events for all spawned processes with clean exit codes (0x0)

**PowerShell Channel Events (66 events):**
- Script block logging (EID 4104) capturing the exact command: `{New-PSDrive -name g -psprovider filesystem -root \\Target\C$}`
- Command invocation logging (EID 4103) showing `New-PSDrive` cmdlet execution with parameters: name="g", PSProvider="filesystem", Root="\\Target\C$"
- Multiple CIM-related alias creation events and Get-CimInstance calls for Win32_LogicalDisk enumeration
- Set-ExecutionPolicy bypass operations typical of test framework activity

**Sysmon Events (47 events):**
- Process creation events (EID 1) for PowerShell processes and whoami.exe execution
- Image load events (EID 7) showing .NET runtime and PowerShell module loading
- Named pipe creation (EID 17) for PowerShell host communication
- Process access events (EID 10) indicating inter-process communication between PowerShell instances
- File creation events (EID 11) for PowerShell profile data

## What This Dataset Does Not Contain

The dataset lacks network-level telemetry that would typically accompany successful SMB admin share access. Notably missing are:

- No Sysmon network connection events (EID 3) to the target host "Target" on SMB ports (445/139)
- No authentication events (EIDs 4624/4625) indicating successful or failed logon attempts to the remote system
- No file system access events showing successful enumeration or file operations on the mapped drive
- No object access auditing events that would indicate successful share access

The absence of network connectivity and authentication events suggests the technique attempt may have failed at the network or authentication level, or the target "Target" was unreachable. The clean process exit codes (0x0) in Security events indicate the PowerShell processes completed without obvious errors, but success of the actual share mapping is unclear from the available telemetry.

## Assessment

This dataset provides excellent visibility into the client-side execution of SMB admin share mapping techniques. The PowerShell script block and command invocation logging capture the exact technique implementation with full parameter visibility. The Security channel provides strong process-level context including privilege usage patterns that are valuable for detection engineering.

However, the dataset's utility is limited by the apparent lack of successful network-level execution. For building comprehensive detections of lateral movement via admin shares, additional telemetry showing successful SMB connections, authentication events, and remote file system access would strengthen the dataset significantly. The data is most valuable for detecting attempt-level indicators rather than successful lateral movement completion.

## Detection Opportunities Present in This Data

1. **PowerShell New-PSDrive UNC Path Detection** - Monitor EID 4103 CommandInvocation events for New-PSDrive cmdlet with Root parameters containing administrative share paths (\\*\C$, \\*\ADMIN$)

2. **Script Block UNC Share Mapping** - Alert on EID 4104 script blocks containing New-PSDrive commands with filesystem providers targeting administrative shares

3. **Process Command Line Administrative Share Access** - Detect Security EID 4688 events with command lines containing PowerShell and UNC paths to administrative shares

4. **Privilege Escalation with Share Access Context** - Correlate Security EID 4703 privilege adjustment events (especially SeBackupPrivilege, SeRestorePrivilege) with PowerShell processes attempting network share access

5. **PowerShell Profile Enumeration Activity** - Monitor combinations of Get-CimInstance Win32_LogicalDisk queries (EID 4103) followed by New-PSDrive commands as potential reconnaissance-to-access patterns

6. **Named Pipe Creation with Network Access Patterns** - Combine Sysmon EID 17 PowerShell pipe creation events with subsequent network-related PowerShell activity as lateral movement preparation indicators
