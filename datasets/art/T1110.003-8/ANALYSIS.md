# T1110.003-8: Password Spraying — Password Spray using Kerbrute Tool

## Technique Context

Password spraying (T1110.003) is a credential access technique where attackers attempt to authenticate to multiple accounts using a small number of common passwords, avoiding account lockouts that typically trigger after repeated failed attempts against a single account. Unlike traditional brute force attacks that hammer one account with many passwords, password spraying spreads authentication attempts across many accounts with few passwords per account.

Kerbrute is a popular Go-based tool that performs Kerberos pre-authentication attacks, including password spraying against Active Directory environments. It's favored by both red teams and real attackers because it's fast, generates minimal network traffic, and can enumerate valid usernames without authentication. The detection community focuses on monitoring for multiple failed authentication events across different accounts from single sources, unusual Kerberos traffic patterns, and the presence of known credential testing tools.

## What This Dataset Contains

This dataset captures the execution of kerbrute for password spraying but shows a critical limitation — the kerbrute.exe binary itself never appears in the process telemetry. The Security channel shows the PowerShell command line that would have executed kerbrute:

```
"powershell.exe" & {cd \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\"
.\kerbrute.exe passwordspray --dc $ENV:userdnsdomain -d $ENV:userdomain \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\passwordspray.txt\" password132}
```

The PowerShell channel captures the script blocks for this execution:
- Script block `fd457f85-0920-4015-9c6a-4ebf5cd432e0` contains the actual kerbrute command
- Script block `691a56e1-b25b-4383-a998-fe70f13ebb19` shows the same command without the `&` operator
- Most other PowerShell events are test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`)

Sysmon captures the PowerShell process creation (EID 1) with PID 9156 that should have spawned kerbrute, along with typical PowerShell .NET assembly loads and Windows Defender DLL loading. Process access events (EID 10) show PowerShell accessing other processes, including the whoami.exe execution captured separately.

## What This Dataset Does Not Contain

The dataset is missing the most critical evidence: kerbrute.exe process creation and its network authentication attempts. There are no Sysmon EID 1 events showing kerbrute.exe execution, no EID 3 network connections to domain controllers, and no EID 22 DNS queries for DC resolution. 

This absence suggests Windows Defender likely blocked kerbrute.exe execution before it could start. The PowerShell process exits with status 0x0, but we see no error telemetry that would indicate explicit blocking. The sysmon-modular config's include-mode filtering for ProcessCreate would have captured kerbrute.exe if it executed, as it's a known attack tool.

Critically absent are Security channel authentication events (4624/4625) that would show the actual password spray attempts against domain accounts, which is the core evidence defenders need to detect this technique.

## Assessment

This dataset demonstrates a common challenge in security telemetry — the gap between execution intent and actual technique completion. While it provides excellent visibility into the PowerShell command lines that attempted to launch a password spraying attack, it fails to capture the technique's actual execution and impact.

The data is moderately useful for detecting password spraying attempts at the tool deployment stage, as the kerbrute command line is clearly visible in both Security 4688 events and PowerShell script block logging. However, it provides no telemetry for detecting successful password spraying operations, which typically rely on authentication log analysis and network behavior detection.

For detection engineering, this dataset highlights the importance of layered monitoring — command-line detection can catch attempts even when endpoint protection prevents execution, but defenders still need authentication monitoring and network detection to catch successful password spraying campaigns.

## Detection Opportunities Present in This Data

1. **Kerbrute Command Line Detection** - Security EID 4688 and PowerShell EID 4104 events contain the explicit "kerbrute.exe passwordspray" command line with targeting parameters

2. **Password Spraying Tool Indicators** - Command line contains classic password spray syntax including domain targeting (`--dc $ENV:userdnsdomain`), domain specification (`-d $ENV:userdomain`), and wordlist usage

3. **PowerShell Script Block Analysis** - EID 4104 events capture the complete attack command for behavioral analysis and threat hunting

4. **Credential Testing File Paths** - References to "passwordspray.txt" wordlist file in ExternalPayloads directory indicates credential attack preparation

5. **Domain Environment Enumeration** - Use of `$ENV:userdnsdomain` and `$ENV:userdomain` environment variables suggests domain environment reconnaissance preceding credential attacks
