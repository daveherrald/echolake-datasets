# T1482-7: Domain Trust Discovery — Get-ForestTrust with PowerView

## Technique Context

T1482 (Domain Trust Discovery) via PowerView's `Get-ForestTrust` extends domain trust enumeration
to the forest level. Where `Get-DomainTrust` (T1482-6) shows trusts for a single domain,
`Get-ForestTrust` maps the entire forest trust topology. This distinction matters for attackers
planning lateral movement across forest boundaries. Like T1482-6, this test uses the IEX + IWR
in-memory download pattern to load PowerView from GitHub.

## What This Dataset Contains

This dataset captures telemetry from a PowerView `Get-ForestTrust` execution attempt via
in-memory download on ACME-WS02. The execution pattern is nearly identical to T1482-6.

**Security channel (4688/4689)** provides the primary evidence. A 4688 event captures the
PowerShell command with `IEX (IWR '...PowerView.ps1' -UseBasicParsing); Get-ForestTrust -Verbose`.
The PowerShell process exits with `0xC0000022` (STATUS_ACCESS_DENIED) — Defender detected and
killed it, identical to the outcome in T1482-6. A preceding cmd.exe exits `0x1`.

**Sysmon channel** (20 events, IDs 1, 7, 8, 10, 11, 17) follows the same structure as T1482-6.
Sysmon ID 8 (CreateRemoteThread) events again appear, reflecting Defender or AMSI instrumentation
hooks in the PowerShell process during the kill sequence. The lower total event count compared to
T1482-6 (20 vs. 25 events) reflects minor variation in the timing of Defender's intervention and
how many DLL loads completed before the process was killed.

**PowerShell channel** (29 events, IDs 4103/4104) contains ART test framework boilerplate only. No
`Get-ForestTrust` execution or PowerView function calls were captured.

## What This Dataset Does Not Contain

- `Get-ForestTrust` output — Defender killed the process before any enumeration ran
- Successful PowerView function calls in the PowerShell channel
- Network connection to GitHub for the IWR download

## Assessment

This dataset captures a **Defender-blocked PowerView forest trust enumeration attempt**. The
outcome is structurally identical to T1482-6: the full GitHub download URL and function name
(`Get-ForestTrust`) are preserved in the Security 4688 command line, and the `0xC0000022` exit
code confirms Defender termination. The value of this dataset alongside T1482-6 is the paired
coverage of both `Get-DomainTrust` and `Get-ForestTrust` in the same collection run — an
adversary performing both in sequence would produce a detectable behavioral sequence.

## Detection Opportunities Present in This Data

- **Security 4688**: PowerShell command line containing `Get-ForestTrust` with the PowerSploit
  GitHub URL is a direct IOC; `Get-ForestTrust` alone is unusual in enterprise environments
- **Security 4689**: Exit code `0xC0000022` on a PowerShell process that loaded `Get-ForestTrust`
  in its command line confirms Defender detection — useful for measuring detection coverage
- **Sysmon ID 1**: powershell.exe with IEX/IWR pattern; command line visible in the process
  create event with full URL and function call
- **Sysmon ID 8**: CreateRemoteThread in PowerShell during Defender termination — same artifact
  pattern as T1482-6; consistent across both tests, strengthening it as a behavioral indicator
- **Behavioral sequence**: `Get-DomainTrust` (T1482-6) followed by `Get-ForestTrust` (T1482-7)
  within seconds is a recognizable forest reconnaissance sequence
