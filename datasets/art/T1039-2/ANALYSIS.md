# T1039-2: Data from Network Shared Drive — Copy a sensitive File over Administrative share with Powershell

## Technique Context

T1039 Data from Network Shared Drive represents one of the most common methods adversaries use to collect data once they've gained initial access to an environment. This technique involves accessing shared folders, mapped drives, or administrative shares (like C$, ADMIN$) to locate and exfiltrate sensitive information. It's particularly effective in enterprise environments where data is commonly stored on network file shares for collaboration.

The technique is foundational to many attack campaigns because it leverages legitimate Windows functionality. Attackers often use it after credential harvesting or lateral movement to systematically search for valuable data across the network. Detection engineers focus on monitoring for unusual access patterns to administrative shares, large data transfers, and PowerShell commands that interact with UNC paths. The community emphasizes looking for access to shares from unexpected hosts, enumeration of multiple shares, and copying files with sensitive extensions or names.

## What This Dataset Contains

This dataset captures a PowerShell-based attempt to copy a file from an administrative share that ultimately fails. The core technique is visible in Security Event ID 4688 showing the PowerShell command line: `"powershell.exe" & {copy-item -Path "\\127.0.0.1\C$\Windows\temp\Easter_Bunny.password" -Destination "$Env:TEMP\Easter_egg.password"}`.

The execution chain shows multiple PowerShell processes spawned by the test framework, with Sysmon EID 1 capturing the key process creation: ProcessId 2916 with the full Copy-Item command targeting the localhost administrative share `\\127.0.0.1\C$`. The PowerShell channel provides detailed telemetry including the script block creation (EID 4104) showing the Copy-Item cmdlet with the UNC path and local destination.

Most importantly, PowerShell EID 4103 captures the actual Copy-Item execution with parameters and the failure: `NonTerminatingError(Copy-Item): "Cannot find path '\\127.0.0.1\C$\Windows\temp\Easter_Bunny.password' because it does not exist."` This shows the technique was attempted but failed because the source file wasn't present.

The Sysmon data includes comprehensive process access events (EID 10) showing PowerShell accessing child processes, image loads for .NET components, and named pipe creation typical of PowerShell execution. Multiple PowerShell processes are visible with various ProcessGuids, indicating the test framework's multi-stage execution.

## What This Dataset Does Not Contain

The dataset lacks the actual network activity that would occur during successful share access. There are no Sysmon EID 3 (Network Connection) events showing SMB connections to the target share, which would normally be present when accessing remote or administrative shares. This absence is likely because the source file didn't exist, preventing the full network interaction.

Missing are file system events that would show successful file copying - no Sysmon EID 11 events for the destination file creation in `$Env:TEMP\Easter_egg.password`. The Security channel doesn't contain EID 5140 (Network Share Access) or EID 5145 (Network Share Object Access) events that would typically fire when accessing administrative shares, even localhost ones.

The dataset also lacks evidence of SMB authentication or session establishment that would normally precede administrative share access. Additionally, there are no Windows Defender alerts or blocks, suggesting the technique attempt was too brief or benign to trigger AV detection beyond the normal PowerShell monitoring.

## Assessment

This dataset provides excellent detection engineering value specifically for PowerShell-based data collection attempts, even failed ones. The combination of Security 4688 command-line logging, PowerShell script block logging (4104), and command invocation logging (4103) creates multiple detection opportunities. The Sysmon process creation and access events add additional context about the execution environment.

While the technique didn't succeed, the telemetry demonstrates what defenders should monitor for when attackers attempt to access administrative shares via PowerShell. The clear visibility into the Copy-Item parameters, UNC paths, and error conditions makes this valuable for understanding both successful and failed data collection attempts. The dataset would be stronger with network telemetry showing SMB connections, but the PowerShell logging provides the core detection opportunities needed.

## Detection Opportunities Present in This Data

1. **PowerShell Administrative Share Access**: Security 4688 and Sysmon 1 events showing PowerShell command lines containing administrative share UNC paths like `\\*\C$\`, particularly when combined with file copy operations

2. **Copy-Item with UNC Paths**: PowerShell 4103 CommandInvocation events showing Copy-Item cmdlet usage with network paths, especially administrative shares (`C$`, `ADMIN$`, etc.)

3. **PowerShell Script Block Execution**: PowerShell 4104 events containing script blocks with `copy-item` and UNC path parameters, indicating potential data collection activities

4. **Suspicious File Names in Copy Operations**: Detection of PowerShell copy operations targeting files with sensitive naming patterns like "password", "secret", "confidential" in the path or filename

5. **PowerShell Process Access Patterns**: Sysmon 10 events showing PowerShell processes accessing child processes during file operations, indicating potential automated data collection scripts

6. **Failed Network Share Access**: PowerShell 4103 NonTerminatingError events indicating failed attempts to access network shares, which could represent reconnaissance or failed data collection attempts
