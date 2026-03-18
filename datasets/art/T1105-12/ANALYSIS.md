# T1105-12: Ingress Tool Transfer — svchost writing a file to a UNC path

## Technique Context

T1105 Ingress Tool Transfer is a fundamental command and control technique where adversaries transfer tools or files from an external system into a compromised environment. This technique is critical to most attack chains, as adversaries typically need to introduce additional payloads, tools, or data after initial compromise. The detection community focuses heavily on identifying unusual file transfers, particularly those involving suspicious processes, uncommon network protocols, or transfers to/from unusual locations.

This specific test simulates an adversary copying a legitimate binary (cmd.exe) to masquerade as svchost.exe, then using that renamed binary to write content to a UNC path (\\localhost\c$\). The technique demonstrates how attackers might use renamed system binaries to blend in with normal system processes while performing file operations that could transfer data or tools.

## What This Dataset Contains

The dataset captures a PowerShell-orchestrated file transfer technique with several key components:

1. **Process chain execution**: PowerShell (PID 18044) spawns cmd.exe (PID 18128) with the command line `"cmd.exe" /c copy C:\Windows\System32\cmd.exe C:\svchost.exe & C:\svchost.exe /c echo T1105 > \\localhost\c$\T1105.txt`

2. **Binary masquerading**: Sysmon EID 11 shows cmd.exe creating `C:\svchost.exe` at 19:30:54.778, demonstrating the copy operation of cmd.exe to masquerade as the legitimate svchost service process

3. **UNC path file creation**: The renamed svchost.exe attempts to write "T1105" to `\\localhost\c$\T1105.txt`, representing ingress tool transfer via network share

4. **Process access monitoring**: Sysmon EID 10 events show PowerShell accessing both the whoami.exe process (PID 38172) and cmd.exe process (PID 18128) with full access rights (0x1FFFFF), indicating process injection capabilities

5. **Failed execution**: Security EID 4689 shows cmd.exe exiting with status 0x1, indicating the UNC write operation failed, likely due to permissions or network restrictions

The Security channel provides complete process lineage with command-line arguments, while Sysmon captures the file creation events and process access attempts that would be critical for detecting this technique.

## What This Dataset Does Not Contain

Several important elements are missing from this dataset:

1. **Network connection events**: No Sysmon EID 3 events are present, so we cannot observe the actual network connection attempt to \\localhost\c$\

2. **File access failures**: While we see the process exit with error code 0x1, there are no explicit file access denied events (Security EID 4656/4658) that would show the failed UNC path write

3. **The actual svchost.exe execution**: Although svchost.exe is created, there are no Sysmon EID 1 or Security EID 4688 events showing the renamed binary executing, suggesting it may have been blocked or failed to run

4. **Target file creation evidence**: No Sysmon EID 11 showing T1105.txt creation, confirming the transfer failed

5. **DNS resolution**: No Sysmon EID 22 events for localhost resolution, though this may be handled locally without DNS

## Assessment

This dataset provides excellent telemetry for detecting T1105 ingress tool transfer techniques, particularly those involving binary masquerading and UNC path operations. The combination of Security process creation events with full command-line visibility and Sysmon file creation monitoring creates multiple detection opportunities. The failed execution actually enhances the dataset's value by showing how defensive controls can prevent the technique while still generating valuable detection telemetry.

The process chain visibility is particularly strong, showing the complete attack flow from PowerShell through cmd.exe to the attempted svchost.exe masquerading. The Sysmon process access events (EID 10) provide additional context about PowerShell's interaction with spawned processes.

## Detection Opportunities Present in This Data

1. **Binary masquerading detection**: Monitor Sysmon EID 11 file creation events where legitimate system binaries (cmd.exe, powershell.exe) are copied to suspicious names like svchost.exe in non-system directories

2. **Suspicious process command lines**: Alert on Security EID 4688 with command lines containing both file copy operations and UNC path writes, especially when combining copy commands with renamed executables

3. **UNC path file operations**: Detect cmd.exe or other shell processes attempting to write files to network shares, particularly \\localhost\c$\ which may indicate lateral movement preparation

4. **Process injection indicators**: Monitor Sysmon EID 10 process access events where PowerShell accesses cmd.exe with full rights (0x1FFFFF), indicating potential process manipulation

5. **Failed execution correlation**: Correlate Security EID 4689 process exit events with non-zero exit codes (0x1) following suspicious command executions to identify blocked attack attempts

6. **PowerShell spawning system utilities**: Alert on PowerShell processes spawning cmd.exe with complex command lines involving file operations and network paths

7. **File creation in root directories**: Monitor Sysmon EID 11 for executable files created in C:\ root directory, especially those mimicking legitimate system process names
