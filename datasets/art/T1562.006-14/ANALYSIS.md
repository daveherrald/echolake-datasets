# T1562.006-14: Indicator Blocking — Block Cybersecurity Communication via Windows Name Resolution Policy Table

## Technique Context

MITRE ATT&CK T1562.006 (Indicator Blocking) includes actions that prevent security tools from
communicating with their cloud backends. The Windows Name Resolution Policy Table (NRPT) is
a DNS policy mechanism originally designed for DirectAccess/VPN split-DNS scenarios. Adversaries
can abuse it to redirect security vendor DNS queries to `127.0.0.1`, silencing endpoint
protection cloud lookups, telemetry uploads, and threat intelligence queries without disabling
the security product itself. This technique has been used in targeted intrusions where
disabling antivirus would be too conspicuous.

## What This Dataset Contains

The test calls `Add-DnsClientNrptRule` to redirect DNS resolution for the Microsoft Defender
for Endpoint management endpoint:

```powershell
Add-DnsClientNrptRule -Namespace ".endpoint.security.microsoft.com"
  -NameServers 127.0.0.1 -Comment "Silenced by Name Resolution Policy Table"
```

Security EID 4688 records the `powershell.exe` process containing the full `Add-DnsClientNrptRule`
invocation with namespace and nameserver arguments. Sysmon EID 1 captures the same with parent
process context. Sysmon EID 8 (CreateRemoteThread) fires, showing `powershell.exe` injecting
a thread into an unknown process (target process exited before Sysmon could resolve the image
name, appearing as `<unknown process>`).

Sysmon EID 13 (RegistryValueSet) records side-effect writes to HKCR and HKLM service security
descriptors by `SecurityHealthService.exe` and `services.exe`, which are OS reactions to the
test environment rather than the technique itself. Security EID 4624/4627/4672 documents the
SYSTEM logon token context under which the test ran.

## What This Dataset Does Not Contain (and Why)

No DNS query events (Sysmon EID 22) reflect the NRPT rule taking effect — NRPT changes apply
to future DNS queries, not the act of adding the rule. No `netsh` or registry activity appears
directly; `Add-DnsClientNrptRule` uses a WMI/COM provider internally. The PowerShell
scriptblock log (EID 4104) contains only ART test framework boilerplate in this dataset — the
`Add-DnsClientNrptRule` invocation was captured in the Security EID 4688 command line but
did not produce a distinct EID 4104 scriptblock beyond the outer wrapper (the command appears
in the 4688 process command line). No Sysmon EID 12/13 for the NRPT registry path appears
because `Add-DnsClientNrptRule` writes to
`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DnsClient\DnsPolicyConfig` and that path
is not in the sysmon-modular registry include filter.

## Assessment

The test executed its payload. The key evidence is in Security EID 4688: the full
`Add-DnsClientNrptRule` command with the `.endpoint.security.microsoft.com` namespace is
captured verbatim. The EID 8 CreateRemoteThread event is an artifact of the PowerShell
process and does not indicate additional malicious activity. The Sysmon EID 13 events for
service security descriptor updates are OS background activity triggered by `SecurityHealthService`
reacting to environmental changes.

Detection based solely on registry monitoring would miss this technique for the reason noted
above. Process command-line monitoring (EID 4688 or Sysmon EID 1) is the most reliable
detection vector here.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `powershell.exe` command line containing `Add-DnsClientNrptRule`
  with `-NameServers 127.0.0.1` or known security vendor domains as `-Namespace` values.
- **Sysmon EID 1**: Same command in process create with parent process chain showing
  `powershell.exe` → `powershell.exe` spawn.
- **Behavioral**: `Add-DnsClientNrptRule` redirecting any security vendor domain
  (`.microsoft.com`, `.crowdstrike.com`, `.sentinelone.net`, etc.) to loopback is a
  near-zero false-positive pattern.
- **Sysmon EID 8**: CreateRemoteThread from `powershell.exe` into an unknown process during
  DNS policy modification is an anomaly worth investigating even without the command line.
