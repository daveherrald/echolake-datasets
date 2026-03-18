# T1558.003-2: Kerberoasting — Rubeus kerberoast

## Technique Context

Kerberoasting (T1558.003) allows any domain-authenticated user to request Kerberos TGS tickets for service accounts with registered Service Principal Names (SPNs). The resulting tickets are encrypted with the service account's password hash and can be cracked offline. This test uses Rubeus, a purpose-built C# Kerberos toolkit that performs the attack natively using Windows SSPI, without loading a PowerShell module or making LDAP queries through .NET managed code. Rubeus interacts directly with the Kerberos subsystem and writes output to a file.

## What This Dataset Contains

The dataset spans approximately 5 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 163 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {klist purge
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus.exe" kerberoast /outfile:"C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt"}
```

**Process chain** (Security EID 4688): The sequence is `whoami.exe` (pre-check), the outer `powershell.exe` carrying the above command, then `klist.exe purge` (to purge the Kerberos ticket cache before the attack, ensuring fresh ticket requests), then `cmd.exe /c ... rubeus.exe kerberoast /outfile:...`, followed by a second `whoami.exe` (post-check), and finally a cleanup `powershell.exe` removing the output file. Six EID 4688 events cover this full chain.

Sysmon EID 1 confirms the same chain. The outer PowerShell is tagged `technique_id=T1059.001,technique_name=PowerShell`. Note that Rubeus.exe itself does not appear in the Sysmon EID 1 samples — the sysmon-modular process creation filter uses include rules for known-suspicious patterns, and Rubeus may not match any active include rule by image name alone. It would still appear in Security EID 4688 with command-line auditing.

**Sysmon events include:**
- EID 7 (Image Load): 25 events — .NET CLR assemblies loading into the outer PowerShell process
- EID 10 (Process Access): 6 events — PowerShell opening child processes with `0x1fffff` full access rights, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): `MsMpEng.exe` writing a temp file to `C:\Windows\Temp\01dcb6331e553006`, and PowerShell writing `StartupProfileData-NonInteractive` and `StartupProfileData-Interactive` to the SYSTEM profile's PowerShell directory
- EID 17 (Pipe Create): Three `\PSHost.*` named pipes for two PowerShell process instantiations

**PowerShell channel** (111 events): 108 EID 4104 script block records and 3 EID 4103 pipeline execution records. The 4103 records confirm `Set-ExecutionPolicy Bypass` and a `Write-Host "DONE"` call indicating the attack completed. The PowerShell 4104 log reflects only test framework boilerplate — Rubeus executes as a native binary via cmd.exe, so the kerberoasting logic itself does not appear in script block logging.

**Application channel**: Two EID 15 events from the Windows Security Center, one each for the two PowerShell processes.

**Security channel**: Six EID 4688 events documenting the complete process chain including `klist.exe purge` and the cmd.exe invocation of `rubeus.exe kerberoast /outfile:`.

## What This Dataset Does Not Contain

No Kerberos ticket request events (Security EID 4769) are present. Rubeus ran against the acme.local domain and executed the kerberoast command, but no SPN-bearing accounts were available for harvesting or the output file was empty. The Security channel contains only process creation events — there is no evidence in the workstation log of TGS tickets being issued. TGS request logging (EID 4769) occurs on the domain controller, not the workstation.

Rubeus.exe execution itself is not captured by Sysmon EID 1 in the sample set, though it would appear in the full Security EID 4688 dataset. The ART framework calls Rubeus through `cmd.exe /c`, and the cmd.exe process create event is present.

## Assessment

This dataset records the most forensically significant variant of Kerberoasting in this test group. Unlike the PowerShell-download variants (tests 1, 6, 7), Rubeus is a pre-staged binary that executes natively without downloading code at runtime. The attack evidence is primarily in the Security and Sysmon process creation logs rather than in PowerShell script block logs.

Compared with the defended variant (datasets/art/T1558.003-2), this dataset contains substantially more events: 163 versus 82 in the defended run. The defended dataset had Sysmon counts of 31, Security 14, and PowerShell 37. Here the Sysmon count is 44, Security 6, and PowerShell 111. The defended run did not block Rubeus execution via AMSI (it is a binary, not a script), so the process chain is similar — the primary difference is more PowerShell framework boilerplate in the undefended run and slightly more Sysmon image load events.

The `klist purge` step before `rubeus.exe kerberoast` is operationally significant: an attacker clearing the Kerberos ticket cache before requesting new TGS tickets reduces the chance of hitting a cached ticket and ensures the DC issues a fresh encrypted ticket. This behavioral pattern — `klist purge` immediately followed by Rubeus or a similar tool — is itself a detection opportunity.

## Detection Opportunities Present in This Data

**Security EID 4688 command-line audit** records the full command: `rubeus.exe kerberoast /outfile:C:\AtomicRedTeam\...\rubeus_output.txt`. The `kerberoast` argument to rubeus.exe, combined with an `/outfile` parameter, is a direct indicator of offline cracking intent.

**`klist.exe purge` preceding a Kerberos attack tool** is a distinctive behavioral sequence. The Security EID 4688 record for `klist.exe purge` appears just before the Rubeus invocation and can be correlated by parent process GUID.

**File creation at `ExternalPayloads\rubeus_output.txt`** (visible in the cleanup 4688 event removing it) indicates that Rubeus wrote output to disk. Pre-cleanup, a file containing Kerberos ticket hashes in Hashcat format would exist at that path.

**Process lineage**: `cmd.exe` spawned from `powershell.exe` running as `NT AUTHORITY\SYSTEM`, which itself has a `powershell.exe` parent, executing a binary in `C:\AtomicRedTeam\ExternalPayloads\` — the non-standard binary path combined with the SYSTEM context and the Kerberos-related tool name are high-confidence indicators.

**Sysmon EID 7 image loads** into the test framework PowerShell confirm the SYSTEM execution context and provide a process GUID that can be used to pivot to the Rubeus child process in Security EID 4688.
