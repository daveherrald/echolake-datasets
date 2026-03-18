# T1558.003-5: Kerberoasting — Request All Tickets via PowerShell

## Technique Context

Kerberoasting (T1558.003) at scale involves requesting TGS tickets for every SPN-bearing account in the domain. This test combines the SPN enumeration approach from test 3 with the .NET ticket-request approach from test 4: it uses `setspn.exe` to enumerate all SPNs, pipes the output through PowerShell to extract service names, then iterates through each SPN and calls `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken` for each one. This all-accounts variant is more aggressive than requesting a single ticket and is the pattern associated with bulk kerberoasting.

## What This Dataset Contains

The dataset spans approximately 6 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 110 events across Sysmon, Security, PowerShell, Application, and TaskScheduler channels.

**The attack command**, captured in Security 4688 and PowerShell 4104:
```
powershell.exe & {Add-Type -AssemblyName System.IdentityModel
setspn.exe -T %USERDNSDOMAIN% -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }}
```

PowerShell 4104 also captures the inner lambda executed per SPN:
```
{ New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

As with test 4, the invocation runs as `NT AUTHORITY\SYSTEM`, which lacks a domain Kerberos context. The `KerberosRequestorSecurityToken` constructor would fail for each SPN attempted.

**Process chain** (Security 4688):
1. `whoami.exe` — ART test framework pre-check
2. `powershell.exe` — obfuscation-tagged (`T1027/Obfuscated Files or Information` in Sysmon 1, reflecting the pipeline structure)
3. `setspn.exe -T %USERDNSDOMAIN% -Q */*` — SPN enumeration
4. `taskhostw.exe` and `sppsvc.exe` — Windows background processes that happened to start during the window (not related to the attack)

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033), `powershell.exe` (T1027), `setspn.exe` (not in Sysmon include rules — appears only in Security 4688)
- Event 7: .NET CLR and System.IdentityModel assembly loads
- Event 10: PowerShell accessing `whoami.exe`, `powershell.exe` itself, and `setspn.exe` child processes
- Event 11: PowerShell profile data and Delivery Optimization file writes
- Event 13 (Registry Set): `svchost.exe` writing `HKLM\...\Schedule\TaskCache\Tree\Microsoft\Windows\Flighting\OneSettings\RefreshCache\Index` — a scheduled task cache update unrelated to the attack
- Event 17: `\PSHost.*` named pipes

**TaskScheduler events**: A `Microsoft\Windows\Flighting\OneSettings\RefreshCache` scheduled task fired coincidentally during the collection window. Events 100, 102, 107, 129, 140, 200, 201 represent the full lifecycle (triggered, started, launched, action completed, finished) of this unrelated OS maintenance task.

**Application event 16394**: `Offline downlevel migration succeeded` — a Windows Update compatibility event, unrelated to the attack.

## What This Dataset Does Not Contain (and Why)

**No Kerberos TGS tickets.** The execution context is SYSTEM without a domain Kerberos TGT, so the `KerberosRequestorSecurityToken` constructor fails for each iterated SPN. In a real attack with a domain user account, this technique would generate multiple Security 4769 events on the DC.

**No PowerShell 4100 error events.** Unlike test 4, no error event was captured — possibly because the error occurred in the pipeline and was silently handled, or because the collection window ended before errors were logged.

**Setspn.exe not in Sysmon Event 1.** The sysmon-modular include config does not match `setspn.exe`. Coverage comes from Security 4688.

**The TaskScheduler and Application events are OS background activity**, not attack-related, captured because the collection window was broad enough to include them.

## Assessment

This test combines SPN enumeration and bulk ticket request into a single PowerShell pipeline, which represents a more sophisticated and stealthy approach than using dedicated offensive tooling. The technique runs entirely in memory with no external binaries. The execution failed at the credential layer for the same reason as test 4 (SYSTEM context), but the enumeration step (`setspn.exe`) ran successfully. The dataset demonstrates that real environments contain background OS noise (scheduled tasks, app events) alongside attack activity.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` command line combining `setspn.exe`, `Select-String '^CN'`, and `KerberosRequestorSecurityToken` — the full pipeline is a canonical kerberoasting pattern
- **PowerShell 4104**: Script block containing `Add-Type -AssemblyName System.IdentityModel` and the `ForEach` iterator calling `KerberosRequestorSecurityToken` per SPN
- **Security 4688**: `setspn.exe` with `-T <domain> -Q */*` as a direct subprocess of `powershell.exe` running as SYSTEM
- **Sysmon 7**: System.IdentityModel assembly loaded into PowerShell — unusual for workstations
- **Sysmon 10**: PowerShell accessing `setspn.exe` child — `T1055.001` DLL injection rule match
- **Behavioral**: The combination of SPN enumeration immediately followed by bulk Kerberos token requests is a high-confidence kerberoasting indicator, even without dedicated tooling
