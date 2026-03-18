# T1571-1: Non-Standard Port — Testing Usage of Uncommonly Used Port with PowerShell

## Technique Context

T1571 (Non-Standard Port) covers adversary use of non-standard network ports for
command-and-control communication to evade port-based network filtering. This test uses
PowerShell's `Test-NetConnection` cmdlet to establish a TCP connection to `google.com`
on port 8081 — an uncommonly used port that would typically bypass firewall rules
permitting only standard HTTP (80) and HTTPS (443). While `Test-NetConnection` is a
legitimate diagnostic cmdlet, its use to probe non-standard ports to external services
under SYSTEM context mimics C2 connectivity testing that adversaries perform after
gaining initial access to verify egress path availability.

## What This Dataset Contains

**Sysmon EID 22** — three DNS query events from PowerShell for `google.com`:

> First query: `QueryStatus: 0` — `QueryResults: ::ffff:142.251.35.142;`
>
> Second query: `QueryStatus: 1460` (WSAETIMEDOUT) — `QueryResults: -`
>
> Third query: `QueryStatus: 0` — `QueryResults: 2607:f8b0:400f:800::200e;::ffff:142.251.35.142;`

The sequence of DNS queries is diagnostic. The first query returns an IPv4 address; the
second times out (suggesting a brief connectivity disruption or DNS retry); the third
returns both IPv6 and IPv4 addresses. The 28-second window (01:59:51Z to 02:00:19Z)
reflects the timeout behavior of `Test-NetConnection` waiting for the TCP response on
port 8081 before reporting failure.

**Security EID 4688** — process creation for `powershell.exe`, `whoami.exe`, and
`svchost.exe` under SYSTEM. The PowerShell command line is visible:

> `New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Security EID 4624** — Type 5 (Service) logon for SYSTEM:

> `Account Name: SYSTEM | Logon Type: 5 | Elevated Token: Yes`

**Security EID 4627** — group membership for the SYSTEM logon, listing
`%{S-1-5-32-544}` (Administrators), `%{S-1-1-0}` (Everyone), `%{S-1-5-11}`
(Authenticated Users), `%{S-1-16-16384}` (System Mandatory Level).

**Security EID 4672** — special privileges assigned to the SYSTEM logon:
`SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeDebugPrivilege`, and other
high-value privileges confirming the full SYSTEM token context.

**PowerShell EID 4104** — the test payload is captured:

> `{Test-NetConnection -ComputerName google.com -port 8081}`

Plus test framework boilerplate: `Set-StrictMode` fragments, NetSecurity module cmdlet
definitions (large multi-part script blocks from module loading), and CIM alias
definitions (`gcim`, `ncim`, `rcim`, etc.).

## What This Dataset Does Not Contain (and Why)

**No Sysmon EID 3 (network connection).** Sysmon's include-mode ProcessCreate filter
did not generate a Sysmon EID 1 for this PowerShell invocation, and the network
connection logging configuration may require a corresponding process create to correlate.
More importantly, `Test-NetConnection` on port 8081 to an external host may have been
blocked at the network layer (the DNS timeout in the second query suggests intermittent
connectivity), preventing a fully established TCP connection that Sysmon would record.

**No Sysmon EID 1 for PowerShell.** The sysmon-modular include-mode rules did not match
the `Test-NetConnection` command line pattern, so the process create was not captured
by Sysmon. Security EID 4688 provides command-line coverage.

**No actual C2 channel.** `Test-NetConnection` is a diagnostic probe; it does not
establish persistent communication. The test verifies port reachability, not a protocol
exchange.

**No outbound TCP connection record.** The `QueryStatus: 1460` timeout on one of the
three DNS queries and the absence of a Sysmon EID 3 suggest port 8081 was not reachable
or the connection timed out before Sysmon recorded it.

## Assessment

This is a sparse dataset by volume but contains interesting multi-source correlation
material. The DNS query sequence — including a timeout — for an external public hostname
from SYSTEM-context PowerShell is anomalous. The Security logon events (4624, 4627,
4672) for the SYSTEM service logon associated with the test execution are consistent
background artifacts. The primary detection value is in the 4104 script block showing
the port probe and the DNS queries to a public hostname from a SYSTEM-context process
running `Test-NetConnection`.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104** — `Test-NetConnection` with a non-standard port to an external
  hostname under SYSTEM context is suspicious; legitimate system services do not use
  this cmdlet for external connectivity testing.
- **Sysmon EID 22** — DNS queries for public hostnames (`google.com`) from
  `powershell.exe` running as SYSTEM, especially in conjunction with a concurrent
  `Test-NetConnection` script block, indicate port probing activity.
- **DNS timeout pattern** — a `QueryStatus: 1460` (WSAETIMEDOUT) immediately followed
  by a successful retry query for the same name suggests the test was retrying after
  a connection failure on the non-standard port, which is distinct from normal browsing.
- **Security EID 4688 command line** — if the PowerShell command line is available via
  4688 (it is here), the `Test-NetConnection ... -port 8081` string is directly queryable.
- **Duration-based detection** — the 28-second execution window for what should be a
  near-instantaneous cmdlet reflects TCP timeout behavior; process duration anomaly
  can supplement command-line detection.
