# T1110.003-1: Password Spraying — Password Spray all Domain Users

## Technique Context

Password spraying is a brute force attack technique where attackers attempt to authenticate to multiple accounts using a small number of commonly used passwords. Unlike traditional brute force attacks that target a single account with many password guesses, password spraying distributes attempts across many accounts to avoid account lockout policies. This technique is particularly effective in Active Directory environments where organizations often have predictable password policies and users frequently choose weak passwords like "Password123" or seasonal passwords like "Spring2020".

The detection community focuses on identifying patterns of authentication failures across multiple accounts from single sources, unusual authentication timing patterns, and the use of tools that automate credential testing. Password spraying often generates distinctive network traffic patterns and authentication logs that can be detected through correlation analysis.

## What This Dataset Contains

This dataset captures a password spraying attack using the "net use" command to test the password "Spring2020" against domain users. The key evidence is found in Security event 4688, which shows the creation of a cmd.exe process with the command line:

`"cmd.exe" /c @FOR /F %%n in (%%temp%%\users.txt) do @echo | set/p=. & @net use %%logonserver%%\IPC$ /user:"%%userdomain%%\%%n" "Spring2020" 1>NUL 2>&1 && @echo [*] %%n:Spring2020 && @net use /delete %%logonserver%%\IPC$ > NUL`

The process chain shows:
- PowerShell (PID 29744) as the parent process
- cmd.exe (PID 26740) executing the password spray loop
- The command references a user list file at `%temp%\users.txt`
- Exit status 0x2 indicates the command failed

Sysmon captures complementary process creation evidence in event ID 1, showing the same cmd.exe execution with full command line details. The dataset also contains process access events (Sysmon EID 10) showing PowerShell accessing both whoami.exe and cmd.exe processes.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy and Set-StrictMode scriptblocks) with no evidence of the actual attack script content.

## What This Dataset Does Not Contain

This dataset lacks several critical elements for complete password spray analysis:

- **Authentication logs**: No Security event IDs 4624/4625 showing actual login attempts or failures
- **Network authentication events**: No Kerberos authentication events (4768/4769/4771) that would show the credential testing attempts
- **Source user list**: The referenced `%temp%\users.txt` file creation is not captured
- **Network connections**: No Sysmon EID 3 events showing SMB/IPC$ connections to domain controllers
- **Success indicators**: The cmd.exe exit code 0x2 suggests the attack failed, but no successful authentication telemetry is present

The absence of authentication events is particularly notable since password spraying's primary detection value comes from correlating multiple authentication failures across accounts.

## Assessment

This dataset provides limited utility for password spray detection engineering. While it captures the attack tool execution and command line arguments clearly through Security 4688 and Sysmon EID 1, it lacks the authentication telemetry that forms the foundation of effective password spray detection. The process creation events are valuable for understanding attacker tooling and techniques, but insufficient for building robust detections that identify the core malicious behavior.

The dataset would be significantly stronger with authentication logs from a domain controller showing the actual credential testing attempts, network connection logs showing SMB traffic patterns, and file creation events capturing the user enumeration preparation phase.

## Detection Opportunities Present in This Data

1. **Command line pattern detection**: Monitor for cmd.exe processes with command lines containing "net use", "IPC$", password strings, and FOR loop constructs typical of automated credential testing

2. **Process chain analysis**: Detect PowerShell spawning cmd.exe with net use commands, particularly when combined with file redirection operators (>NUL, 2>&1)

3. **Temp file enumeration patterns**: Alert on processes referencing user list files in temporary directories (%temp%\users.txt, %temp%\accounts.txt)

4. **Net use automation indicators**: Identify command lines that combine net use with password parameters and automated cleanup (/delete commands)

5. **PowerShell-to-cmd execution pattern**: Monitor for PowerShell processes spawning cmd.exe with credential-related command line arguments

6. **Process access correlation**: Correlate Sysmon EID 10 process access events from PowerShell to multiple child processes during credential testing phases
