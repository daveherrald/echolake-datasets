# T1615-5: Group Policy Discovery — MSFT Get-GPO Cmdlet

## Technique Context

T1615 (Group Policy Discovery) using the Microsoft-provided `Get-GPO` cmdlet from the GroupPolicy PowerShell module represents the lowest-friction approach to GPO enumeration on domain-joined Windows systems. Unlike PowerView or WinPwn, `Get-GPO` is a legitimate Microsoft-signed cmdlet available on systems with the Group Policy Management Console (GPMC) or Remote Server Administration Tools (RSAT). Its use is harder to distinguish from legitimate administration.

## What This Dataset Contains

This dataset captures execution of `Get-GPO -Domain $ENV:userdnsdomain -All` (appending output to a temp file) as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

**Sysmon (36 events)** — Includes:
- EID 7 (image load): Standard PowerShell DLL loads; notably includes Defender DLL tagged T1574.002 and system management assembly tagged T1059.001
- EID 17 (named pipe): PSHost pipes for both the outer test framework and test PowerShell instances
- EID 10 (process access): PowerShell accessing another process, tagged T1055.001
- EID 1 (process create):
  - `whoami.exe` tagged `technique_id=T1033` — test framework identity check
  - `powershell.exe` with command line: `"powershell.exe" & {Get-GPO -Domain $ENV:userdnsdomain -All >> $env:temp\GPO_Output.txt}` — tagged `technique_id=T1059.001`
- EID 11 (file create): PowerShell startup profile writes and, importantly, `$env:temp\GPO_Output.txt` — the file where GPO enumeration results are written

**Security log (10 events)** — EID 4688/4689 process lifecycle events for `whoami.exe` and the test PowerShell process, plus EID 4703 token right adjustments.

**PowerShell log (45 events)** — EID 4104 captures the key script block:
```
& {Get-GPO -Domain $ENV:userdnsdomain -All >> $env:temp\GPO_Output.txt}
```
EID 4103 module logging records `Set-ExecutionPolicy Bypass` and the standard test framework boilerplate stubs. No additional Get-GPO specific cmdlet invocation logging appears beyond the script block itself.

## What This Dataset Does Not Contain (and Why)

- **GPO enumeration results** — The content written to `$env:temp\GPO_Output.txt` is not captured in Windows event logs. Object access auditing is disabled in this environment (audit_policy: object_access: none), so no file write events appear in the Security log for the output file.
- **LDAP queries to the domain controller** — `Get-GPO -All` performs LDAP queries against the DC, but no network connection or Kerberos ticket events appear in this dataset. The collection scope does not include network events for this test.
- **GroupPolicy module load events** — The GroupPolicy module loading does not generate Sysmon image load events that are distinct from normal PowerShell module loading in this dataset.
- **Cleanup of output file** — The ART test writes output to a temp file; no file deletion event appears in this dataset for that file.

## Assessment

This test completed successfully — `Get-GPO -All` is a legitimate cmdlet that works on domain-joined systems with GPMC installed. The Sysmon EID 1 captures the full command line including the redirection to `GPO_Output.txt`, and the PowerShell EID 4104 script block provides matching visibility. This is the most "living-off-the-land" approach among the T1615 tests, using only Microsoft-signed tools. The file creation of `GPO_Output.txt` in `%TEMP%` is captured by Sysmon EID 11 and represents an artifact that could persist for later exfiltration.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / PowerShell EID 4104**: `Get-GPO` with `-All` flag in a PowerShell script block executed from a SYSTEM context is anomalous; legitimate administrators would typically run this interactively from a user account.
- **Sysmon EID 11**: File creation of `GPO_Output.txt` (or similar GPO-named files) in `%TEMP%` by a SYSTEM PowerShell process indicates data staging following GPO enumeration.
- **Security EID 4688**: A second `powershell.exe` spawned from another `powershell.exe` running as SYSTEM with an inline command block is a behavioral pattern consistent with automated test frameworkes and offensive frameworks.
- **Correlation**: The sequence `whoami.exe` → `powershell.exe` with `Get-GPO -All` → file write to `%TEMP%` represents a multi-step discovery-and-stage chain detectable through event correlation.
