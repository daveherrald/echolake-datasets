# T1558.004-1: AS-REP Roasting — Rubeus asreproast

## Technique Context

AS-REP Roasting (T1558.004) targets Active Directory accounts that have Kerberos pre-authentication disabled — the `DONT_REQ_PREAUTH` flag in the `userAccountControl` attribute. When pre-authentication is disabled, anyone can send an AS-REQ for that account without providing credentials, and the domain controller responds with an AS-REP containing data encrypted with the account's password hash. That encrypted blob can be taken offline for cracking. Unlike Kerberoasting, no valid domain credentials are required — the attacker only needs network access to the domain controller.

This test uses Rubeus with the `asreproast` command. Rubeus queries Active Directory for accounts with pre-authentication disabled, then directly sends AS-REQ packets to the domain controller for each discovered account.

## What This Dataset Contains

The dataset spans approximately 5 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 147 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus.exe" asreproast /outfile:"C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt"}
```

Sysmon EID 1 tags the outer PowerShell process `technique_id=T1059.001,technique_name=PowerShell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, the attacking `powershell.exe` carrying the cmd.exe-wrapped Rubeus command, `cmd.exe /c C:\AtomicRedTeam\...\ExternalPayloads\rubeus.exe asreproast /outfile:...`, a second `whoami.exe`, and finally a cleanup `powershell.exe` with `Remove-Item "C:\AtomicRedTeam\...\ExternalPayloads\rubeus_output.txt" -ErrorAction Ignore`. Five EID 4688 events cover this chain. The cleanup step's script block is also visible in PowerShell EID 4104: `{Remove-Item "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt" -ErrorAction Ignore}`.

**Sysmon events include:**
- EID 7 (Image Load): 25 events — .NET CLR assemblies into the test framework PowerShell
- EID 10 (Process Access): 5 events — PowerShell opening child processes with full access rights, tagged `T1055.001/Dynamic-link Library Injection`
- EID 17 (Pipe Create): Two `\PSHost.*` pipes for the two PowerShell instances
- EID 3 (Network Connect): 1 event — `MsMpEng.exe` making an outbound connection to `48.211.71.198:443` (Microsoft Defender cloud telemetry, not attack traffic)

**PowerShell channel** (100 events): 99 EID 4104 records and 1 EID 4103. The 4103 confirms `Set-ExecutionPolicy Bypass`. The cleanup `Remove-Item` call appears in 4104 blocks, confirming the attack generated an output file that was subsequently deleted. The attack itself (Rubeus executing as a native binary via cmd.exe) does not appear in script block logs.

**Application channel**: Two EID 15 Security Center reports.

## What This Dataset Does Not Contain

No AS-REP responses or Kerberos pre-authentication failure events are present in this workstation's Security log. The critical telemetry for AS-REP Roasting success — Security EID 4768 (Kerberos Authentication Service request) logged on the domain controller — does not appear here. The workstation Security channel contains only EID 4688 process creation events.

Rubeus.exe itself does not appear in Sysmon EID 1 sample output, but the cmd.exe invocation with the full Rubeus command line is captured in both Security EID 4688 and (via the parent PowerShell's EID 1 record) in Sysmon.

The `MsMpEng.exe` network connection to `48.211.71.198:443` is Windows Defender cloud telemetry, not attack traffic. Despite Defender being disabled for active scanning, the background service process continued making cloud connectivity checks during the test window.

## Assessment

AS-REP Roasting with Rubeus provides the most direct path to AS-REP ticket extraction available in these tests. The attack requires no initial credentials (unlike Kerberoasting which requires at least a valid domain user), making it valuable as an initial access enabler. The dataset captures the full execution chain including the artifact cleanup step.

The Rubeus `asreproast` command versus the `kerberoast` command (T1558.003-2) differs in one key way: `asreproast` sends raw AS-REQ packets to the DC for accounts with `DONT_REQ_PREAUTH` set, while `kerberoast` requests TGS tickets after authenticating. The DC-side telemetry differs accordingly (EID 4768 vs 4769), but both are absent from this workstation log.

Compared with the defended variant (datasets/art/T1558.004-1, Sysmon: 48, Security: 12, PowerShell: 43), the undefended dataset is similar in structure. The defended run had more Security events (12 vs 5) — the additional events in the defended run likely include Defender-related process creation activity. The undefended dataset's 147 total events versus 103 defended reflects primarily the additional PowerShell boilerplate (100 vs 43 PS events).

The `Remove-Item` cleanup step is forensically notable: the attacker (or ART framework) deletes the output file containing the AS-REP hashes. The file creation event (from Rubeus writing output) would exist in the full Sysmon dataset, and the `Remove-Item` call is logged in PowerShell EID 4104.

## Detection Opportunities Present in This Data

**Security EID 4688 command-line audit**: `rubeus.exe asreproast /outfile:` is a precise indicator. The `/outfile` parameter confirms the intent to capture and exfiltrate or crack the results offline.

**cmd.exe wrapping an offensive binary** in `C:\AtomicRedTeam\ExternalPayloads\` is a process lineage indicator. In a real attack, the binary path would differ, but the pattern of `powershell.exe → cmd.exe → [attack binary] asreproast` is detectable.

**Cleanup evidence in PowerShell EID 4104**: The `Remove-Item` script block targeting a path that previously held Rubeus output is visible even after the file is deleted. This sequence — write output file, then delete it — is a behavioral indicator of credential harvest and anti-forensics.

**MsMpEng.exe cloud connectivity**: The Sysmon EID 3 network connection from `MsMpEng.exe` to `48.211.71.198:443` occurred during the attack window. While this is a Defender telemetry beacon rather than attack traffic, its presence confirms the timing context and shows that Defender's background service was active even with real-time protection disabled.

**Rubeus output file path**: The path `C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt` appears in both the attack command line and the cleanup. A file at this path containing AS-REP hash material would be detectable by file integrity monitoring or EDR file creation rules.
