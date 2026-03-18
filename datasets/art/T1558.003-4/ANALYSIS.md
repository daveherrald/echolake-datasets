# T1558.003-4: Kerberoasting — Request A Single Ticket via PowerShell

## Technique Context

Kerberoasting (T1558.003) can be performed directly through the .NET framework without external tooling. The `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` class, part of the Windows Communication Foundation (WCF) stack, allows a .NET application to request a Kerberos TGS ticket for a given SPN. This test uses `Add-Type` to load the `System.IdentityModel` assembly and then directly instantiates a `KerberosRequestorSecurityToken` for a single SPN — in this case `HTTP/<LogonServer FQDN>` derived from environment variables. This approach is notable because it requires no external tools, only a default Windows PowerShell installation.

## What This Dataset Contains

The dataset spans approximately 4 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 81 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688 and PowerShell 4104:
```
powershell.exe & {Add-Type -AssemblyName System.IdentityModel
$ComputerFQDN=$env:LogonServer.trimStart('\') + "." + $env:UserDnsDomain
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/$ComputerFQDN"}
```

**The ticket request failed.** PowerShell 4100 records the error:
> `Exception calling ".ctor" with "1" argument(s): "The NetworkCredentials provided were unable to create a Kerberos credential, see inner exception for details."`
> `Fully Qualified Error ID = ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand`

The failure occurs because the process runs as `NT AUTHORITY\SYSTEM`, which does not have a domain user Kerberos context. `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` requires an authenticated domain user ticket-granting ticket (TGT) in the calling process's session, which SYSTEM does not have in this configuration.

**Process chain** (Security 4688):
1. `whoami.exe` — ART test framework identity pre-check
2. `powershell.exe` — child process carrying the full .NET Kerberos request

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033) and `powershell.exe` (T1059.001)
- Event 7: .NET CLR and System.IdentityModel assembly loads — `mscoree.dll`, `clr.dll`, `mscorlib`, and related WCF assemblies loaded into `powershell.exe` as part of `Add-Type -AssemblyName System.IdentityModel`
- Event 10: PowerShell accessing child processes (T1055.001 pattern)
- Event 11: PowerShell startup profile data files
- Event 17: `\PSHost.*` named pipes

**PowerShell 4104** contains the full script block including the `Add-Type` and `New-Object KerberosRequestorSecurityToken` call.

## What This Dataset Does Not Contain (and Why)

**No Kerberos TGS ticket was issued.** The `KerberosRequestorSecurityToken` constructor threw an exception because SYSTEM has no domain Kerberos context. In a real attack scenario with a domain user account, this would have resulted in a TGS request and Security 4769 on the DC.

**No network connection to the DC.** Because the Kerberos request failed at the .NET credential layer before any Kerberos wire protocol messages were sent, there are no DNS or network events to the domain controller.

**No Sysmon Event 22 (DNS).** Unlike test 3, which used `setspn.exe` and triggered LDAP lookups, this test failed before reaching the network.

## Assessment

The attack technique — using .NET `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` — is legitimate tradecraft that does not require external binaries and would typically evade tools looking for known offensive tools. In this execution, the attempt failed because the test runs as SYSTEM rather than as a domain user. The failure mode is informative: it demonstrates that this technique requires a domain user context, and tests conducted as SYSTEM do not fully exercise it. The dataset retains value as a record of the command-line and assembly-loading patterns associated with this approach.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` with command line referencing `System.IdentityModel`, `KerberosRequestorSecurityToken`, and a constructed SPN (`HTTP/$ComputerFQDN`) — unusual .NET Kerberos class usage from a workstation
- **PowerShell 4104**: Full script block logging captures the `Add-Type -AssemblyName System.IdentityModel` and `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken` call — detectable via script block content matching
- **PowerShell 4100**: `ConstructorInvokedThrowException` error from `NewObjectCommand` — the error itself reveals the technique even in the failure case
- **Sysmon 7**: Loading of `System.IdentityModel` and WCF-related assemblies into PowerShell — unusual assembly load pattern that does not occur in normal PowerShell usage
