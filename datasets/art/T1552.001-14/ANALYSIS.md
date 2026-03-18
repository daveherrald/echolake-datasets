# T1552.001-14: Credentials In Files — List Credential Files via Command Prompt

## Technique Context

Credentials in Files (T1552.001) includes enumerating Windows Credential Manager storage files. This test performs the same enumeration as T1552.001-13 but uses `cmd.exe` with `dir /a:h` rather than PowerShell `Get-ChildItem -Hidden`. The use of `cmd.exe` for credential file enumeration is a meaningful variation: it bypasses PowerShell script block logging for the enumeration commands themselves, relying on Security 4688 command-line auditing and Sysmon process creation for detection coverage.

## What This Dataset Contains

The attack command is captured in Security 4688 and Sysmon EID 1 (tagged `technique_id=T1083,technique_name=File and Directory Discovery`):

> `"cmd.exe" /c dir /a:h C:\Users\%USERNAME%\AppData\Local\Microsoft\Credentials\ & dir /a:h C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Credentials\`

The full command uses the `%USERNAME%` environment variable and chains both Local and Roaming Credential Manager paths with `&`. The Security 4688 record resolves this exactly as shown. Sysmon EID 1 captures `cmd.exe` with `RuleName: technique_id=T1083` — the Sysmon-modular include rule for file and directory discovery commands fired on `cmd.exe`, providing automatic technique tagging.

A `whoami.exe` process creation precedes the cmd.exe (ART identity pre-check, EID 1 tagged `technique_id=T1033`). The PowerShell log contains 38 events that are entirely test framework boilerplate: `PSMessageDetails`, `ErrorCategory_Message`, and `OriginInfo` script block fragments with no substantive content, plus two `Set-ExecutionPolicy Bypass` invocations. No PowerShell-layer evidence of the credential enumeration exists because the enumeration was done via cmd.exe, not PowerShell.

The 36 Sysmon events: 27 EID 7 image loads (single PowerShell parent + cmd.exe child, though cmd.exe does not load .NET CLR), 3 EID 17 pipe creates, 2 EID 11 file creates, 2 EID 1 process creates, 2 EID 10 process access events.

## What This Dataset Does Not Contain (and Why)

The `dir` command output is not logged — there is no file content capture in these event sources, and object access auditing is disabled. Like T1552.001-13, the SYSTEM context means user Credential Manager files are unlikely to exist in the searched paths, but the absence of output is not directly observable in the event data. The PowerShell log provides no visibility into the enumeration commands themselves because they ran in cmd.exe. There are no network events; this is a local file system operation.

## Assessment

This dataset and T1552.001-13 together illustrate a detection coverage gap: the same credential enumeration performed via PowerShell (`Get-ChildItem -Hidden`) versus via cmd.exe (`dir /a:h`) has markedly different logging profiles. The cmd.exe variant loses PowerShell script block visibility and gains Sysmon technique tagging via the include-mode filter. Security 4688 command-line logging provides the critical compensating control — the `dir /a:h ... Microsoft\Credentials` pattern is fully visible there regardless of which shell is used. The Sysmon `T1083` tag demonstrates the value of technique-aware Sysmon configurations.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon EID 1 command line**: `dir /a:h` targeting `Microsoft\Credentials\` in both Local and Roaming AppData is a specific, low-noise pattern. The `&` chaining of both paths in one command is a behavioral signature.
- **Sysmon EID 1 RuleName `technique_id=T1083`**: The sysmon-modular configuration automatically tags this cmd.exe invocation as File and Directory Discovery, enabling SIEM rules that filter on the RuleName field directly.
- **Parent-child relationship**: `powershell.exe` → `cmd.exe` with a credential-path enumeration command is a detectable process tree. A standalone `cmd.exe` issuing `dir /a:h` against Credential Manager directories is also suspicious without the PowerShell parent.
- **`%USERNAME%` in credential path**: Use of environment variable expansion in a `dir` command targeting credential storage is a useful behavioral signal; legitimate directory listings rarely reference Credential Manager paths.
- **Comparison with T1552.001-13**: Side-by-side, these two datasets demonstrate that PowerShell and cmd.exe produce different evidence profiles for the same attack, reinforcing the need for both PowerShell logging and command-line auditing to achieve equivalent coverage across shell variants.
