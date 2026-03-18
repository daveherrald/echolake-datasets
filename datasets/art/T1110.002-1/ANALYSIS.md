# T1110.002-1: Password Cracking — Password Cracking with Hashcat

## Technique Context

Password Cracking (T1110.002) is a credential access technique where attackers use specialized tools to recover passwords from captured hashes. Attackers commonly obtain password hashes through techniques like DCSync, LSASS dumping, or SAM extraction, then use tools like Hashcat, John the Ripper, or custom scripts to perform dictionary attacks, brute force attacks, or rule-based transformations to crack the hashes back to plaintext passwords. This technique is particularly valuable in post-exploitation scenarios where attackers seek to escalate privileges, move laterally, or establish persistence with legitimate credentials.

The detection community typically focuses on identifying the execution of password cracking tools, unusual file access patterns to password databases, command-line arguments indicating hash formats and attack modes, and the presence of wordlists or rules files commonly used in password attacks.

## What This Dataset Contains

The dataset captures a complete Hashcat password cracking execution with clear process telemetry:

The attack begins with PowerShell execution policy bypass (`Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`) captured in Security 4688 and PowerShell 4103 events. The main attack vector appears through a cmd.exe process with the full Hashcat command line: `"cmd.exe" /c cd C:\AtomicRedTeam\atomics\..\ExternalPayloads\hashcat6\hashcat-6.1.1\hashcat.exe\.. & C:\AtomicRedTeam\atomics\..\ExternalPayloads\hashcat6\hashcat-6.1.1\hashcat.exe -a 0 -m 1000 -r .\rules\Incisive-leetspeak.rule C:\AtomicRedTeam\atomics\T1110.002\src\sam.txt C:\AtomicRedTeam\atomics\T1110.002\src\password.lst`.

This command line reveals key attack parameters: dictionary attack mode (`-a 0`), NTLM hash format (`-m 1000`), leetspeak rule transformations (`-r .\rules\Incisive-leetspeak.rule`), a SAM database file (`sam.txt`), and a password wordlist (`password.lst`). The process chain shows PowerShell spawning cmd.exe which would execute Hashcat, though the cmd.exe process exits with code 0x1 indicating failure.

Sysmon events capture process creation for both whoami.exe (EID 1) and cmd.exe (EID 1), along with process access events (EID 10) showing PowerShell accessing both child processes with full access rights (0x1FFFFF). Additional telemetry includes PowerShell module loading (EID 7) and pipe creation (EID 17) for PowerShell's internal operations.

## What This Dataset Does Not Contain

The dataset lacks Hashcat process creation events in Sysmon, likely because the cmd.exe process failed (exit code 0x1) before successfully launching Hashcat. The sysmon-modular configuration's include-mode filtering for ProcessCreate may not have patterns matching hashcat.exe specifically, though the cmd.exe execution was captured due to its LOLBin status.

File access events for the SAM database and wordlist files are absent, suggesting either Sysmon file monitoring isn't configured for these paths or the files weren't actually accessed due to the execution failure. Network events that might occur during rule file downloads or result exfiltration are not present. The PowerShell script block logging contains only test framework boilerplate (Set-StrictMode calls) without the actual attack payload, indicating the technique was executed through direct command execution rather than PowerShell scripting.

## Assessment

This dataset provides excellent telemetry for detecting password cracking attempts, particularly around the command-line patterns and process relationships. The Security 4688 events with full command-line logging are the strongest detection source here, capturing the complete Hashcat syntax with hash type, attack mode, and file paths. The process access events in Sysmon EID 10 add valuable context about parent-child process relationships.

While the actual Hashcat execution appears to have failed, the attempt telemetry is comprehensive enough for building robust detections. The command-line artifacts alone contain multiple high-fidelity indicators including tool names, hash format identifiers, and characteristic file extensions (.txt, .rule, .lst).

## Detection Opportunities Present in This Data

1. **Hashcat Command Line Detection** - Security EID 4688 command lines containing "hashcat.exe" with characteristic parameters like "-m" (hash mode), "-a" (attack mode), and "-r" (rules file)

2. **Password Hash File Access Patterns** - Process command lines referencing files with names like "sam.txt", "ntds.dit", or other common password database filenames in Security EID 4688

3. **Password Cracking Tool Arguments** - Command lines containing specific hash type identifiers like "-m 1000" (NTLM), "-m 1800" (SHA512), or other Hashcat mode numbers

4. **Wordlist and Rules File Usage** - Command lines referencing password lists (*.lst, *.txt) combined with rules files (*.rule) indicating dictionary attacks

5. **Process Chain Analysis** - PowerShell or cmd.exe spawning processes with password cracking tool names in Sysmon EID 1 and Security EID 4688

6. **High-Privilege Process Access** - Sysmon EID 10 events showing processes accessing other processes with full rights (0x1FFFFF) from password cracking tools

7. **Execution Policy Bypass Correlation** - PowerShell execution policy changes (EID 4103) followed by suspicious child process creation within short time windows
