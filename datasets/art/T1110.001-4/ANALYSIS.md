# T1110.001-4: Password Guessing — Password Brute User using Kerbrute Tool

## Technique Context

T1110.001 (Password Guessing) is a credential access technique where adversaries attempt to gain access to accounts through trial-and-error password attacks. Kerbrute is a popular tool in the offensive security community for performing Kerberos pre-authentication attacks against Active Directory environments. Unlike traditional brute force attacks that generate failed logon events, Kerberos pre-authentication attacks can enumerate valid usernames and attempt password guessing with minimal logging on the domain controller. The detection community focuses on identifying the tool's network traffic patterns, command-line execution, and any authentication events that do occur during these attacks.

## What This Dataset Contains

This dataset captures the execution of kerbrute from PowerShell but notably lacks the actual kerbrute execution itself. The key events present are:

**Process Creation Chain**: Security event 4688 shows PowerShell spawning with the command line `"powershell.exe" & {cd \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\" .\kerbrute.exe bruteuser --dc $ENV:userdnsdomain -d $ENV:userdomain $env:temp\bruteuser.txt TestUser1}`, indicating the intended kerbrute execution with bruteuser mode targeting TestUser1.

**PowerShell Activity**: EID 4104 script blocks show the kerbrute command being prepared: `& {cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads" .\kerbrute.exe bruteuser --dc $ENV:userdnsdomain -d $ENV:userdomain $env:temp\bruteuser.txt TestUser1}`. The PowerShell channel also contains extensive boilerplate from Set-StrictMode and Set-ExecutionPolicy commands.

**Process Termination**: Multiple Security 4689 events show PowerShell processes exiting with status 0x0, suggesting normal completion rather than error conditions.

**System Discovery**: A Sysmon EID 1 event captures whoami.exe execution, likely part of the test framework rather than kerbrute functionality.

## What This Dataset Does Not Contain

The dataset is missing critical evidence of the actual kerbrute execution. There are no Sysmon ProcessCreate events for kerbrute.exe itself, which should have been captured given the sysmon-modular config's include rules. This suggests either:

1. Windows Defender blocked kerbrute execution before it could launch
2. The kerbrute.exe binary was not present in the expected path
3. The PowerShell script failed to execute the kerbrute command successfully

Additionally missing are:
- Network connection events (Sysmon EID 3) that would show Kerberos traffic to domain controllers
- Any authentication-related events (Security 4768, 4771, 4776) that successful or failed Kerberos pre-auth attempts would generate
- File access events showing kerbrute reading the bruteuser.txt password list
- Any DNS queries for domain controller discovery

## Assessment

This dataset provides limited value for detection engineering focused on kerbrute attacks. While it captures the PowerShell command-line evidence of kerbrute invocation, the absence of the actual tool execution significantly reduces its utility. The command-line artifacts in Security 4688 and PowerShell script blocks represent the most valuable detection data present, but defenders would need additional datasets showing successful kerbrute execution to build comprehensive detections. The dataset would be substantially more valuable if it included the network traffic patterns, process execution of kerbrute itself, and any resulting authentication events that characterize this technique in real-world scenarios.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection**: Monitor Security EID 4688 and PowerShell EID 4104 for command lines containing "kerbrute" and common kerbrute arguments like "bruteuser", "--dc", "-d"

2. **Suspicious PowerShell Script Block Content**: Alert on PowerShell script blocks executing external tools from paths like "ExternalPayloads" with credential attack parameters

3. **Process Chain Analysis**: Detect PowerShell processes spawning with embedded commands that change directory to tool repositories and execute credential attack utilities

4. **File Path Indicators**: Monitor for references to common penetration testing directory structures like "AtomicRedTeam\atomics\..\ExternalPayloads"

5. **Kerbrute Execution Attempts**: Create detections for any process creation events where the image name contains "kerbrute" regardless of execution success
