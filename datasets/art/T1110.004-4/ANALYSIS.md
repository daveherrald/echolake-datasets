# T1110.004-4: Credential Stuffing — Brute Force:Credential Stuffing using Kerbrute Tool

## Technique Context

T1110.004 Credential Stuffing represents a specific variant of brute force attacks where adversaries systematically attempt authentication using lists of known username/password combinations obtained from previous data breaches. Unlike traditional brute force attacks that try many passwords against a single account, credential stuffing leverages the reality that users often reuse passwords across multiple services. Kerbrute is a popular tool for performing Kerberos-based credential attacks, including credential stuffing against Active Directory environments. The detection community focuses on identifying failed authentication patterns, unusual authentication timing, authentication attempts from unexpected sources, and the use of known attack tools like Kerbrute.

## What This Dataset Contains

This dataset captures an incomplete credential stuffing attempt using the Kerbrute tool. The PowerShell script block logging (EID 4104) reveals the attack command: `.\kerbrute.exe bruteforce --dc $ENV:userdnsdomain -d $ENV:userdomain "C:\AtomicRedTeam\atomics\..\ExternalPayloads\bruteforce.txt"`. Security event 4688 shows the PowerShell process creation with the full command line: `"powershell.exe" & {cd \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\"\n.\kerbrute.exe bruteforce --dc $ENV:userdnsdomain -d $ENV:userdomain \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\bruteforce.txt\"}`.

The Sysmon data shows the PowerShell process chain (EID 1) with process GUIDs and command lines, along with .NET runtime loading events (EID 7) indicating PowerShell execution. Security events show normal process termination (EID 4689) with exit status 0x0 for the PowerShell processes and 0x1 for cmd.exe processes. Process access events (EID 10) show PowerShell accessing child processes, which is normal behavior.

## What This Dataset Does Not Contain

Critically, this dataset lacks any evidence of the actual Kerbrute execution or its authentication attempts. There are no Sysmon ProcessCreate events for kerbrute.exe, no Security authentication events (4624/4625), no Kerberos authentication events (4768/4769/4771), and no network connection events showing communication with domain controllers. The cmd.exe processes exit with status 0x1, suggesting the Kerbrute execution failed or was blocked. The absence of the expected kerbrute.exe process creation in Sysmon data suggests either the tool was not found, execution was blocked by Windows Defender, or the attack failed for other reasons. The sysmon-modular configuration may have filtered out kerbrute.exe if it doesn't match the include patterns for ProcessCreate events.

## Assessment

This dataset provides limited value for understanding successful credential stuffing attacks, as it primarily captures the setup phase rather than the actual attack execution. The PowerShell command line and script block logging provide excellent visibility into the attack intention and tool usage, making these the most valuable detection artifacts present. However, the absence of authentication events, network activity, or the target tool execution significantly limits its utility for building comprehensive detections. The data would be more valuable if it included successful tool execution with resulting authentication attempts against the domain controller.

## Detection Opportunities Present in This Data

1. **PowerShell script block detection** - Monitor EID 4104 for script blocks containing "kerbrute", "bruteforce", or references to credential attack tools with command-line parameters

2. **Suspicious PowerShell command lines** - Detect Security EID 4688 events where PowerShell command lines reference external security tools like "kerbrute.exe" with brute force parameters

3. **Tool staging detection** - Alert on PowerShell processes changing directory to external payload locations (e.g., "\AtomicRedTeam\atomics\..\ExternalPayloads\") combined with executable invocation

4. **Failed execution patterns** - Correlate PowerShell processes spawning with cmd.exe exits showing status 0x1, potentially indicating blocked or failed attack tool execution

5. **PowerShell module loading anomalies** - Monitor for System.Management.Automation.dll loading (EID 7) in contexts where PowerShell is being used to launch external attack tools
