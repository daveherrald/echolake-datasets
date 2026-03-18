# T1110.001-1: Password Guessing — Brute Force Credentials of single Active Directory domain users via SMB

## Technique Context

T1110.001 Password Guessing represents one of the most fundamental and persistent attack vectors in modern cybersecurity. Attackers use this technique to gain unauthorized access by systematically attempting authentication with common passwords, weak credentials, or leaked password lists. In enterprise environments, SMB-based password guessing is particularly concerning because successful authentication can provide immediate network access and privilege escalation opportunities.

The detection community focuses heavily on identifying patterns of authentication failures, rapid-fire login attempts, and the use of common password lists. Key detection indicators include multiple failed logon events from the same source, authentication attempts against multiple accounts, and the characteristic network traffic patterns of SMB brute-force tools. This technique often precedes lateral movement and privilege escalation, making early detection critical for containment.

## What This Dataset Contains

This dataset captures a straightforward SMB password guessing attack executed through native Windows commands. The attack begins with PowerShell spawning a cmd.exe process that executes the command:

```
"cmd.exe" /c echo Password1> passwords.txt & echo 1q2w3e4r>> passwords.txt & echo Password!>> passwords.txt & echo Spring2022>> passwords.txt & echo ChangeMe!>> passwords.txt & @FOR /F "delims=" %p in (passwords.txt) DO @net use %logonserver%\IPC$ /user:"%userdomain%\%username%" "%p" 1>NUL 2>&1 && @echo [*] %username%:%p && @net use /delete %logonserver%\IPC$ > NUL
```

The Security log captures the complete process chain: PowerShell (PID 22516) → cmd.exe (PID 22556) → multiple net.exe processes attempting each password. Sysmon EID 1 events show five net.exe process creations with command lines like `net use %%logonserver%%\IPC$ /user:"ACME\ACME-WS02$" "Password1 "`, each attempting a different password from the predefined list.

Notably, all net.exe processes exit with status 0x2 (as shown in Security EID 4689 events), indicating authentication failures. Sysmon EID 11 shows the creation of `C:\Windows\Temp\passwords.txt` containing the password list used for iteration.

## What This Dataset Does Not Contain

This dataset lacks the network-level evidence that would typically accompany SMB brute-force attacks. There are no Sysmon EID 3 (Network Connection) events showing the actual SMB traffic to the domain controller, and no Security EID 4625 (Failed Logon) events that would normally be generated on the target system. This suggests the authentication attempts may have been blocked at the network level or the target system logs aren't captured.

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy) rather than the actual attack script, indicating the technique was executed via direct command execution rather than PowerShell scripting. Additionally, there are no Success Audit events (EID 4624) showing any successful authentication, confirming all password attempts failed.

## Assessment

This dataset provides excellent visibility into the process execution patterns of command-line based password guessing attacks. The combination of Security 4688 events with full command-line logging and Sysmon process creation events creates a complete picture of the attack methodology. The clear parent-child process relationships and explicit password attempts in command lines make this ideal for developing process-based detections.

However, the dataset's value is limited for network-based detection development due to the absence of actual SMB authentication traffic. The technique appears to have failed at the network communication level, making this more valuable for detecting attempted brute-force preparation rather than the authentication attempts themselves.

## Detection Opportunities Present in This Data

1. **Command-line password list creation** - Security EID 4688 showing cmd.exe processes creating text files with `echo` commands followed by password-like strings, particularly when executed in rapid succession

2. **Net.exe authentication attempt loops** - Multiple Sysmon EID 1 or Security EID 4688 events showing net.exe processes with `/user:` parameters and different passwords in the command line, especially when spawned from the same parent process

3. **Process chain analysis** - PowerShell spawning cmd.exe which rapidly spawns multiple net.exe processes, indicating scripted authentication attempts rather than normal administrative activity

4. **Temporary file creation patterns** - Sysmon EID 11 showing creation of .txt files in temp directories immediately followed by multiple net.exe executions, suggesting automated password list processing

5. **Process exit code correlation** - Security EID 4689 events showing multiple net.exe processes exiting with status 0x2 (failure) in rapid succession, indicating systematic authentication failures
