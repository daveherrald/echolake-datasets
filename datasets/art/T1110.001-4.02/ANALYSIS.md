# T1110.001-4: Password Guessing — Password Brute User using Kerbrute Tool

## Technique Context

T1110.001 (Password Guessing) covers adversary attempts to access accounts by systematically testing passwords for specific known usernames—distinct from password spraying (one password across many accounts) and credential stuffing (using leaked credential pairs). Password guessing against Active Directory is typically implemented through authentication protocols; Kerberos pre-authentication is a particularly attractive target because it can be tested without directly querying LDAP or touching the domain controller's Security event log (if done carefully with AS-REQ manipulation).

Kerbrute is an open-source Kerberos brute-force tool written in Go. It uses raw Kerberos AS-REQ packets to test credentials, which means it operates at the Kerberos protocol level rather than through Windows authentication APIs. In its `bruteuser` mode, it tests a list of passwords against a single username. The advantages for an adversary: it does not generate Windows logon failure events (EID 4625) on the workstation itself, generates minimal noise, and can test credentials faster than traditional NTLM-based approaches.

This test runs: `kerbrute.exe bruteuser --dc $ENV:userdnsdomain -d $ENV:userdomain $env:temp\bruteuser.txt TestUser1` — testing passwords from a file against the `TestUser1` account in the `acme.local` domain.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled.

**Process Chain (Security EID 4688 / Sysmon EID 1):**

The ART test framework PowerShell (PID 5160) spawns a child PowerShell (PID 5840, tagged `technique_id=T1059.001`) with:

```
"powershell.exe" & {cd "C:\AtomicRedTeam\atomics\..\ExternalPayloads\"
.\kerbrute.exe bruteuser --dc $ENV:userdnsdomain -d $ENV:userdomain $env:temp\bruteuser.txt TestUser1}
```

The command changes directory to `C:\AtomicRedTeam\ExternalPayloads\` and runs `kerbrute.exe` from there. The `--dc` flag uses the `userdnsdomain` environment variable to target the domain controller for `acme.local`.

**File Modification Timestamp (Sysmon EID 2):**

One EID 2 (file creation time changed) event appears in this dataset—the only test in this batch to generate an EID 2. This event fires when a file's creation timestamp is modified, which can be a timestamp manipulation (T1070.006) indicator. In this context it likely reflects kerbrute.exe itself or the bruteuser.txt wordlist file being written with a modification to its timestamp by the ART test framework during setup.

**Process Access (Sysmon EID 10):**

Four events: PID 5160 (test framework) accesses `whoami.exe` (PID 4700) and child PowerShell (PID 5840) with `GrantedAccess: 0x1FFFFF`. The child PowerShell access uses the standard `UNKNOWN` CallTrace pattern.

**Image Loads (Sysmon EID 7):**

Twenty-five DLL load events for the test framework PowerShell (PID 5160)—same count as T1106-2/3, reflecting identical test framework initialization.

**Named Pipe (Sysmon EID 17):**

Three pipe creation events:
- `\PSHost.134180056542786494.5160.DefaultAppDomain.powershell` (test framework)
- `\PSHost.134180056602659148.4160.DefaultAppDomain.powershell` (cleanup shell PID 4160)

**File Creation (Sysmon EID 11):**

Three file creation events, all PowerShell profile writes. Kerbrute itself does not write files during its brute-force operation—its output goes to stdout/stderr.

**PowerShell Script Block Logging (EID 4104/4103):**

116 EID 4104 and 2 EID 4103 events. The higher PowerShell count compared to the T1105 series reflects the T1110 ART module's additional setup code (downloading kerbrute, creating the wordlist).

**Application Log (EID 15):**

One EID 15: Windows Security Center updating Defender status to ON.

## What This Dataset Does Not Contain

The actual Kerberos authentication attempts made by kerbrute.exe are not present in this dataset. Kerbrute operates at the network protocol level using raw AS-REQ packets directed at the domain controller—those packets would appear in DC-side telemetry (Security EID 4768/4771 on the DC, or network capture), not on the workstation's event logs.

There are no Sysmon EID 3 network connection events showing kerbrute's connections to the domain controller. No DNS query (EID 22) shows kerbrute resolving the DC's hostname.

The contents of `bruteuser.txt` (the password wordlist) are not logged. If the brute force succeeded, there would be no success indicator in this dataset—kerbrute's output is console-only.

Kerbrute.exe itself does not appear as a Sysmon EID 1 process creation in the sample—it was launched by the child PowerShell (PID 5840) via directory-change and direct execution, but that EID 1 event was not captured in the sample.

## Assessment

The primary indicator in this dataset is the child PowerShell command line showing `kerbrute.exe bruteuser --dc $ENV:userdnsdomain -d $ENV:userdomain` with a wordlist file path. This is unambiguous: kerbrute is not a legitimate administrative tool, `bruteuser` mode is specifically for password guessing, and the target domain (resolved from the environment) is the live acme.local domain controller.

Compared to the defended variant (sysmon 36, security 10, powershell 45), the undefended dataset has more events across all channels (sysmon 40, security 4, powershell 116). The Security event count is actually lower in the undefended run (4 vs. 10)—this is because Defender's response to kerbrute in the defended variant generates additional process creation events (MpCmdRun.exe quarantine attempts) that appear in the Security channel.

The unique appearance of Sysmon EID 2 (timestamp change) in this dataset is worth noting. This event does not appear in other T1110.001 tests and may reflect kerbrute's file handling behavior during setup.

## Detection Opportunities Present in This Data

**Kerbrute.exe command line (EID 1 / EID 4688):** `kerbrute.exe bruteuser --dc <domain-controller> -d <domain> <wordlist> <username>` is unambiguous offensive tooling. Kerbrute has no legitimate administrative use. The binary name `kerbrute.exe`, the `bruteuser` subcommand, and `--dc` targeting all serve as individual indicators.

**Execution from ExternalPayloads directory (EID 1):** The path `C:\AtomicRedTeam\ExternalPayloads\kerbrute.exe` is test-specific, but any execution of a tool named kerbrute from a staged payload directory warrants immediate investigation. In real attacks, the binary would be staged elsewhere.

**PowerShell cd + run pattern (EID 1):** The pattern of changing directory to a payload staging location and running an executable is a common lateral movement and tool execution pattern. `cd <ExternalPayloads_dir>\n.\kerbrute.exe <args>` in a PowerShell script block is actionable in environments with PowerShell logging.

**DC-side Kerberos pre-authentication failures (EID 4771 on DC):** The complementary detection lives at the domain controller. If kerbrute is testing invalid passwords, the DC will log Kerberos pre-authentication failures (EID 4771) for `TestUser1` from the workstation's IP. The volume and timing of these failures—many in rapid succession from a single source IP—is the primary detection opportunity for this technique.

**Sysmon EID 2 (file creation time modification):** The timestamp modification event warrants correlation with the kerbrute execution timeline to determine if it reflects tool staging or artifact cleanup.
