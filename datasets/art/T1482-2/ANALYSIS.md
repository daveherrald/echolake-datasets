# T1482-2: Domain Trust Discovery — Windows - Discover domain trusts with nltest

## Technique Context

T1482 (Domain Trust Discovery) covers adversary enumeration of Active Directory trust relationships.
This test uses `nltest`, a built-in Windows support tool that can query domain trust information
directly from a domain controller without requiring RSAT tooling. Attackers commonly use nltest as
a living-off-the-land technique because it is present on domain-joined Windows systems by default.

## What This Dataset Contains

This dataset captures telemetry from two consecutive nltest invocations on ACME-WS02:
`nltest /domain_trusts` and `nltest /trusted_domains`, both issued via a cmd.exe wrapper.

**Security channel (4688/4689)** provides the primary evidence. A 4688 event records
`"cmd.exe" /c nltest /domain_trusts & nltest /trusted_domains` launched by the ART test framework.
Separate 4688 events capture each `nltest.exe` child process with its individual arguments.
Critically, both nltest processes exit with status `0x0` — the commands **succeeded**. This
is a meaningful distinction from tests where the tooling fails: successful nltest execution
means the domain controller responded with trust information, making this a higher-fidelity
simulation of real adversary behavior.

**Sysmon channel** (18 events, IDs 1, 7, 10, 11, 17) contributes process execution detail.
Sysmon's include-mode ProcessCreate configuration captured both the cmd.exe wrapper and the
nltest.exe child processes. Sysmon ID 7 (ImageLoad) events document DLL loads for the nltest
process, and ID 10 (ProcessAccess) captures the ART test framework accessing its child processes.

**PowerShell channel** (30 events, IDs 4103/4104) contains exclusively ART test framework boilerplate
— Set-StrictMode scriptblocks and related runtime initialization. No technique-relevant content.

## What This Dataset Does Not Contain

- Network-level DNS or LDAP traffic (no Sysmon ID 22 DNS queries or ID 3 network connections
  in this dataset — the Sysmon network connect rule fired only on non-filtered traffic)
- Domain controller telemetry showing the trust enumeration query being received
- The actual trust relationship data returned by nltest (only telemetry of the process execution)

## Assessment

This dataset represents a **successful execution** with strong telemetry coverage. Both the
cmd.exe wrapper command line (Security 4688) and individual nltest.exe invocations are captured
with full arguments. Exit code `0x0` on both nltest processes confirms the DC responded. This
is among the cleanest T1482 test cases in the collection: nltest is a built-in tool, Defender
does not block it, and command-line auditing captures the arguments in full. The Security log
alone is sufficient for detection.

## Detection Opportunities Present in This Data

- **Security 4688**: nltest.exe with `/domain_trusts` or `/trusted_domains` arguments is a
  well-known indicator; both individual invocations are captured here
- **Security 4688**: cmd.exe command line showing `nltest /domain_trusts & nltest /trusted_domains`
  combined in a single shell command reveals scripted chaining
- **Sysmon ID 1**: nltest.exe process create with parent powershell.exe (via cmd.exe) provides
  the full execution chain including hashes
- **Process chain**: test framework powershell.exe → cmd.exe → nltest.exe is a reliable detection
  pivot; legitimate nltest usage rarely originates from a PowerShell test framework process
