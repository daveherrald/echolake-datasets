# T1552.001-13: Credentials In Files — List Credential Files via PowerShell

## Technique Context

Credentials in Files (T1552.001) includes enumerating Windows Credential Manager storage. The Windows Credential Manager stores credentials in encrypted DPAPI blobs in `%APPDATA%\Microsoft\Credentials\` (roaming) and `%LOCALAPPDATA%\Microsoft\Credentials\` (local). Listing these files reveals which credentials exist and their metadata (creation time, file size) without requiring DPAPI decryption. Attackers use this enumeration step to determine which credentials are worth attempting to decrypt using tools like Mimikatz's `dpapi::cred` module.

## What This Dataset Contains

The attack command is captured in PowerShell 4104, Security 4688, and Sysmon EID 1:

> `$usernameinfo = (Get-ChildItem Env:USERNAME).Value`
> `Get-ChildItem -Hidden C:\Users\$usernameinfo\AppData\Roaming\Microsoft\Credentials\`
> `Get-ChildItem -Hidden C:\Users\$usernameinfo\AppData\Local\Microsoft\Credentials\`

The Security 4688 record shows the full command line with unexpanded variable:
> `"powershell.exe" & {$usernameinfo = (Get-ChildItem Env:USERNAME).Value ...}`

The PowerShell module log (EID 4103) records three `Get-ChildItem` invocations with parameter binding, including the resolved username path `C:\Users\ACME-WS02$\AppData\Roaming\Microsoft\Credentials\` — confirming the execution ran as the `ACME-WS02$` machine account. Two non-terminating errors are logged:

> `Cannot find path 'C:\Users\ACME-WS02$\AppData\Roaming\Microsoft\Credentials\' because it does not exist.`

and the equivalent for the Local path. This confirms the script ran to completion but found no credential files for the SYSTEM/machine account context. The application log contains a single EID 15 event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — a routine Defender state refresh.

The 46 Sysmon events: 35 EID 7 image loads, 4 EID 17 named pipe creates, 3 EID 11 file creates, 2 EID 1 process creates, 2 EID 10 process access events. No DNS queries — this test requires no network access.

## What This Dataset Does Not Contain (and Why)

No credential files were found; the machine account (`ACME-WS02$`) running as SYSTEM does not accumulate Credential Manager entries in the same locations as interactive user accounts. There are no DPAPI decryption events and no credential content was exposed. File read auditing is disabled (`object_access: none`), so even if files had existed, their enumeration would not generate Security log events beyond what is already captured via PowerShell logging. The application event is unrelated to the attack.

## Assessment

This is a fully executed credential file enumeration that ran to completion but found nothing. The dataset is valuable because it captures the complete execution telemetry of a successful script run (no Defender block, no AMSI error) while showing a result of empty output. Unlike the WinPwn tests, this is a benign-looking PowerShell cmdlet sequence using built-in commands. Detection requires recognizing the behavioral pattern — hidden-flag enumeration of Credential Manager directories — rather than matching a known-malicious tool name.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: `Get-ChildItem -Hidden` targeting `Microsoft\Credentials\` directories is a specific, detectable pattern. The combination of roaming and local Credentials paths in a single script block is a strong indicator of credential enumeration intent.
- **PowerShell 4103 module log**: `Get-ChildItem -Hidden -Path C:\Users\*\AppData\...\Microsoft\Credentials\` is detectable as a named cmdlet invocation even without 4104 logging.
- **Security 4688 command line**: The full powershell.exe command line contains the credential path pattern.
- **Execution as SYSTEM**: A SYSTEM-context process performing user credential directory enumeration is anomalous.
- **Error message in 4103**: The `Cannot find path` error for Credential Manager directories is visible in the module log and can be used to confirm execution occurred even when no files are found.
