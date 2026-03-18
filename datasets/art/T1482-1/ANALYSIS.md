# T1482-1: Domain Trust Discovery — Windows - Discover domain trusts with dsquery

## Technique Context

T1482 (Domain Trust Discovery) covers adversary attempts to enumerate trust relationships between
Active Directory domains and forests. This information helps attackers understand the scope of
lateral movement and privilege escalation paths available across domain boundaries. This test
simulates the simplest approach: using `dsquery` to query the directory for objects of class
`trustedDomain`.

## What This Dataset Contains

This dataset captures telemetry from the execution of `dsquery * -filter "(objectClass=trustedDomain)"
-attr *` on ACME-WS02, a Windows 11 domain workstation in acme.local.

**Security channel (4688/4689)** provides the primary process creation evidence. A 4688 event records
`cmd.exe /c dsquery * -filter "(objectClass=trustedDomain)" -attr *` launched by the ART test framework
PowerShell process. A paired 4689 event records cmd.exe exiting with status `0x1`, indicating the
command failed — dsquery is not available on Windows 11 workstations by default (it requires the
RSAT AD DS Tools feature).

**Sysmon channel** (46 events, IDs 1, 7, 10, 11, 17) contributes additional process execution detail.
Sysmon ID 1 (ProcessCreate) captured cmd.exe with the full command line, confirmed by the include-mode
Sysmon configuration matching the cmd.exe/dsquery pattern. Sysmon ID 10 (ProcessAccess) events show
powershell.exe accessing whoami.exe and cmd.exe with GrantedAccess `0x1FFFFF` — full access — which
is standard ART test framework pre-execution enumeration. Sysmon IDs 7, 11, and 17 provide image load, file
create, and pipe activity context for the PowerShell test framework process.

**PowerShell channel** (32 events, IDs 4103/4104) contains exclusively ART test framework boilerplate:
`Set-StrictMode` scriptblocks and `Set-ExecutionPolicy Bypass` invocations. No technique-relevant
PowerShell content is present.

## What This Dataset Does Not Contain

- Successful dsquery output — the tool is not installed on this workstation
- Network traffic or LDAP queries — dsquery never reached the point of contacting a DC
- Domain controller logs — this dataset is workstation-only telemetry
- Sysmon ProcessCreate for dsquery.exe itself — dsquery was not found, so no child process spawned

## Assessment

This dataset captures a **failed execution attempt** with good telemetry fidelity. The command-line
evidence in Security 4688 is complete and unambiguous. The exit code `0x1` distinguishes this from a
successful execution (exit `0x0`) or a Defender termination (exit `0xC0000022`). The Sysmon ProcessCreate
for cmd.exe complements the Security log with hash and parent process GUID data. Defenders can observe
the attempted technique even when the tool is absent from the system.

## Detection Opportunities Present in This Data

- **Security 4688**: cmd.exe command line containing `dsquery` with `objectClass=trustedDomain` filter
  is a high-fidelity indicator regardless of execution outcome
- **Sysmon ID 1**: cmd.exe spawned by powershell.exe with dsquery arguments; includes SHA256 hash of
  cmd.exe for baselining
- **Sysmon ID 10**: powershell.exe performing process access on cmd.exe with GrantedAccess `0x1FFFFF`
  is a general-purpose hunting pivot for process injection and test framework activity
- **Process chain**: powershell.exe → cmd.exe → (dsquery not found) is a detectable parent-child
  relationship for AD enumeration tooling launched via script
