# T1134.001-3: Token Impersonation/Theft — Launch NSudo Executable

## Technique Context

Token impersonation/theft is a privilege escalation and defense evasion technique where attackers duplicate or steal access tokens from privileged processes to execute code with elevated permissions. NSudo is a system administration tool that allows users to run programs with various privilege levels, including TrustedInstaller and System privileges. While legitimate, NSudo can be abused by attackers to bypass UAC and execute commands with elevated privileges without proper authentication. The detection community focuses on monitoring for unusual token manipulation activities, process creation with suspicious parent-child relationships, and the use of known privilege escalation tools like NSudo.

## What This Dataset Contains

The dataset captures the execution attempt of NSudo through PowerShell, but the tool was not present on the system. The key telemetry shows:

**PowerShell Script Execution**: EID 4104 contains the actual script attempting to launch NSudo: `Start-Process "C:\AtomicRedTeam\atomics\T1134.001\bin\NSudoLG.exe" -Argument "-U:T -P:E cmd"` with arguments specifying TrustedInstaller user context (`-U:T`) and elevated privileges (`-P:E`).

**Process Creation Chain**: Security EID 4688 shows PowerShell process creation with the full command line containing the NSudo execution attempt. Sysmon EID 1 captures PowerShell process creation with RuleName matching T1059.001 (PowerShell technique).

**Error Handling**: PowerShell EID 4100 shows the failure: "This command cannot be run due to the error: The system cannot find the file specified" indicating NSudo executable was not present at the expected path.

**Token Privilege Adjustment**: Security EID 4703 documents extensive privilege enablement including SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, and other sensitive privileges that would be associated with token manipulation activities.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing other processes (whoami.exe and another PowerShell instance) with full access rights (0x1FFFFF), demonstrating process inspection capabilities.

## What This Dataset Does Not Contain

The dataset lacks the actual NSudo execution since the binary was missing from the expected location. There are no events showing successful token impersonation, process creation under different security contexts, or the target cmd.exe process that NSudo was supposed to launch with elevated privileges. The technique attempt failed at the file-not-found stage, so no actual privilege escalation occurred. Additionally, there are no Sysmon ProcessCreate events for NSudo itself due to the missing binary, and no token duplication or impersonation events that would occur during successful execution.

## Assessment

This dataset provides excellent telemetry for detecting NSudo execution attempts, even when the tool is absent. The PowerShell script block logging captures the complete command line with NSudo-specific arguments that clearly indicate token impersonation intent. The Security audit logs provide comprehensive process creation details with full command lines, making this technique highly detectable. The privilege adjustment events add valuable context about elevated permissions being enabled. However, the dataset's utility is limited for understanding the full attack chain since the technique didn't complete successfully. For building robust detections, this data is most valuable for identifying preparation and attempt phases of token impersonation attacks.

## Detection Opportunities Present in This Data

1. **NSudo Command Line Detection**: Monitor PowerShell script blocks (EID 4104) and process creation (EID 4688, Sysmon EID 1) for command lines containing "NSudo" with privilege escalation arguments like "-U:T" (TrustedInstaller) or "-P:E" (elevated privileges)

2. **Token Privilege Escalation Monitoring**: Alert on Security EID 4703 events showing multiple sensitive privileges being enabled simultaneously, particularly combinations including SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege

3. **PowerShell Process Access Patterns**: Detect Sysmon EID 10 events where PowerShell processes access other processes with full rights (0x1FFFFF), especially when combined with privilege escalation attempts

4. **Failed Privilege Escalation Tool Execution**: Monitor PowerShell error events (EID 4100) with "file not found" messages referencing paths containing known privilege escalation tools

5. **Process Creation with Suspicious Parent Chains**: Identify PowerShell spawning child processes while attempting to execute privilege escalation tools, even when the tools are missing

6. **Administrative Tool Path References**: Alert on PowerShell script execution attempting to access binaries in paths typically associated with penetration testing frameworks (AtomicRedTeam, NSudo, etc.)
