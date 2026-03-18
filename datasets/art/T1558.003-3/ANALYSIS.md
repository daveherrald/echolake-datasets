# T1558.003-3: Kerberoasting — Extract all accounts in use as SPN using setspn

## Technique Context

Kerberoasting (T1558.003) requires knowing which accounts have SPNs registered before requesting tickets. `setspn.exe` is a built-in Windows administrative tool for managing SPNs on domain objects. Attackers commonly use it for reconnaissance: `setspn -T <domain> -Q */*` queries all SPNs across the domain and returns the service accounts associated with them. This test performs that reconnaissance step in isolation — enumerating potential Kerberoasting targets — without proceeding to ticket requests.

## What This Dataset Contains

The dataset spans approximately 8 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 65 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688:
```
cmd.exe /c setspn -T %USERDNSDOMAIN% -Q */*
setspn -T %USERDNSDOMAIN% -Q */*
```

The `%USERDNSDOMAIN%` environment variable is not expanded in the logged command line — it resolves at execution time to `acme.local`. Note that Security 4688 logs both the `cmd.exe` wrapper invocation and the resulting `setspn.exe` process with its arguments.

**Process chain** (Security 4688):
1. `whoami.exe` — ART test framework pre-check
2. `cmd.exe /c setspn -T %USERDNSDOMAIN% -Q */*` — spawned by the test framework PowerShell
3. `setspn.exe -T %USERDNSDOMAIN% -Q */*` — the actual SPN enumeration

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033) and `cmd.exe` (T1059.003)
- Event 7: .NET CLR image loads
- Event 10: PowerShell parent accessing child processes
- Event 11: PowerShell startup profile file writes
- Event 17: `\PSHost.*` named pipe creation
- Event 22 (DNS Query): Three DNS lookups triggered by `setspn.exe` — queries for `ACME-DC01.acme.local` (resolved to `192.168.4.10`), `%USERDNSDOMAIN%` (failed, status 9560 — the literal env variable was passed before shell expansion), and `_ldap._tcp.Default-First-Site-Name._sites.%USERDNSDOMAIN%.` (failed, same reason). The first successful query confirms DC resolution.

**Note on Sysmon coverage**: `setspn.exe` does not appear as a Sysmon Event 1 because the sysmon-modular include-mode ProcessCreate config does not have a rule matching `setspn.exe`. It is visible only in Security 4688.

**PowerShell 4104** contains only the boilerplate module initialization fragments. No PowerShell-level script executes the setspn command — it runs through `cmd.exe` as a native binary.

## What This Dataset Does Not Contain (and Why)

**No ticket requests.** This test is reconnaissance-only — it enumerates SPN-bearing accounts but does not request TGS tickets. There are no Security 4769 events.

**No setspn.exe in Sysmon Event 1.** The sysmon-modular include config does not match `setspn.exe` by name or pattern. Security 4688 with command-line auditing is the primary source for this process.

**No output file.** The setspn output goes to stdout; no file is written to disk, so there are no Sysmon 11 events for collected data.

**setspn DNS queries appear with unexpanded `%USERDNSDOMAIN%`.** The DNS client queries the literal string rather than the resolved domain in two of the three queries, which is an artifact of how the ART test framework passes the command and how cmd.exe environment expansion interacts with `setspn.exe`'s own LDAP initialization.

## Assessment

This test executed successfully — `setspn.exe` ran (Security 4688 captures it) and queried Active Directory for SPN accounts. The DNS query to `ACME-DC01.acme.local` (192.168.4.10) confirms the workstation contacted the domain controller for the LDAP query. Defender did not intervene here because `setspn.exe` is a legitimate built-in Windows tool. The dataset represents a real, successful SPN enumeration step that a kerberoasting attacker would perform.

## Detection Opportunities Present in This Data

- **Security 4688**: `setspn.exe` with `-Q */*` argument — querying all SPNs domain-wide is anomalous for a workstation and has no legitimate end-user purpose
- **Security 4688**: `cmd.exe /c setspn -T %USERDNSDOMAIN% -Q */*` — the parent command line shows the test framework pattern, but in a real attack this would appear as a user or script invoking setspn directly
- **Sysmon 22 (DNS)**: DNS queries for the DC hostname immediately before or after `setspn.exe` execution — corroborates LDAP/domain activity
- **Sysmon 1**: `cmd.exe` (T1059.003) spawned by `powershell.exe` running as SYSTEM — the process lineage is worth examining even without Sysmon capturing setspn itself
- **Behavioral**: `setspn.exe -Q */*` enumeration from a workstation context, especially when followed by Kerberos ticket requests, is a canonical kerberoasting pre-stage indicator
