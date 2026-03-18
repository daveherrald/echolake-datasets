# T1105-33: Ingress Tool Transfer — Remote File Copy using PSCP

## Technique Context

T1105 Ingress Tool Transfer is a fundamental Command and Control technique where adversaries transfer tools or files from external systems to compromised environments. This technique is critical for multi-stage attacks, allowing threat actors to bring in additional payloads, utilities, or data exfiltration tools. PSCP (PuTTY Secure Copy) is a legitimate SCP client commonly used for secure file transfers over SSH. While legitimate, PSCP's command-line nature and ability to transfer files over encrypted channels makes it attractive for both red teams and real threat actors.

The detection community focuses on monitoring for unexpected usage of file transfer utilities, especially when executed from unusual parent processes, targeting external IP addresses, or transferring files to/from suspicious paths. Key indicators include process creation of transfer utilities, network connections to external hosts, and file system activity creating new executables or archives.

## What This Dataset Contains

This dataset captures a failed PSCP file transfer attempt with excellent visibility into the setup and execution phases. The Security 4688 events show the complete command line execution chain:

1. PowerShell spawning cmd.exe with the full command: `"cmd.exe" /c fsutil file createnew C:\Temp\T1105_scp.zip 1048576 & echo y | C:\AtomicRedTeam\atomics\..\ExternalPayloads\pscp.exe -P 22 -pw atomic C:\Temp\T1105_scp.zip atomic@127.0.0.1:T1105_scp.zip`
2. fsutil.exe creating a 1MB test file: `fsutil file createnew C:\Temp\T1105_scp.zip 1048576`
3. The piped echo command for SSH host key acceptance: `C:\Windows\system32\cmd.exe /S /D /c" echo y "`

Sysmon EID 1 events capture process creation for whoami.exe (system reconnaissance), cmd.exe, and fsutil.exe. Sysmon EID 11 shows file creation of the test payload at `C:\temp\T1105_scp.zip`. The Security events show the primary cmd.exe process exiting with status 0xFF (255), indicating the PSCP transfer failed, likely due to no SSH service running on localhost.

## What This Dataset Does Not Contain

Critically, this dataset lacks evidence of the PSCP process itself executing. No Sysmon EID 1 process creation event exists for pscp.exe, and no network connection events (Sysmon EID 3) show outbound SSH traffic on port 22. The failure occurs because the test attempts to connect to 127.0.0.1:22, but no SSH service is running locally. This means we capture the preparation phase (file creation, command construction) but not the actual transfer attempt or network activity.

The dataset also lacks any Windows Firewall events, DNS resolution attempts for the target host, or authentication-related events that would occur during a successful SSH connection. The sysmon-modular config's ProcessCreate include-mode filtering means pscp.exe might not have been captured even if it executed, as it may not match the suspicious process patterns.

## Assessment

This dataset provides moderate value for detection engineering, particularly for early-stage indicators of file transfer tool usage. The complete command line capture in Security 4688 events is excellent for detecting PSCP usage patterns, including the characteristic password authentication (`-pw`) and port specification (`-P 22`) parameters. The file staging activity with fsutil is well-documented and represents a common preparation pattern.

However, the dataset's utility is limited by the technique's failure to complete. Real-world PSCP usage would generate network connections, authentication events, and potentially Windows Defender alerts that could provide additional detection opportunities. The lack of actual network telemetry means this dataset can't inform network-based detection rules.

## Detection Opportunities Present in This Data

1. **Command line detection for PSCP usage** - Security 4688 events contain full command lines with `pscp.exe` execution, password authentication flags (`-pw`), and external host targeting patterns

2. **File staging behavior** - Sysmon EID 11 file creation events showing creation of files in staging directories (C:\Temp) immediately before transfer tool execution

3. **Process chain analysis** - PowerShell → cmd.exe → fsutil.exe → (attempted pscp.exe) represents a common lateral tool transfer pattern worth monitoring

4. **Fsutil suspicious usage** - Sysmon EID 1 shows fsutil.exe creating files with specific sizes in temporary directories, often used for testing or staging payloads

5. **Tool reconnaissance patterns** - Whoami.exe execution from PowerShell before file transfer attempts indicates pre-transfer system profiling

6. **Command line complexity indicators** - Complex cmd.exe command lines combining file creation, piping, and external tool execution with credential parameters
