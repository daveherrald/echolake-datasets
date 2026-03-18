# T1572-4: Protocol Tunneling — Run ngrok

## Technique Context

MITRE ATT&CK T1572 (Protocol Tunneling) covers encapsulation of command-and-control or
exfiltration traffic within other protocols to evade network-based detection. ngrok is a
legitimate reverse proxy and tunneling service that creates an encrypted tunnel from a
local port to a public ngrok subdomain (`*.ngrok.io`, `*.ngrok-free.app`). Developers use
ngrok to expose local services for testing; adversaries use the same infrastructure to
expose RDP, C2 listeners, or SMB shares to the internet through HTTPS tunnels, bypassing
egress firewall controls entirely.

The attacker's workflow: install the ngrok agent, configure an auth token (which ties the
tunnel to an attacker-controlled ngrok account), start a tunnel pointed at the target
service (here, TCP port 3389 — RDP), and the ngrok cloud creates a publicly-addressable
URL mapped to the local RDP port. Anyone with the URL can reach the internal RDP service
from anywhere on the internet. The tunnel runs over HTTPS (port 443), indistinguishable
from normal web traffic to most firewalls.

This test configures an authtoken (`N/A` as placeholder), starts ngrok tunneling TCP port
3389, waits 5 seconds, then stops it.

In the defended variant, Windows Defender blocked `ngrok.exe` execution. Sysmon EID 1
captured the PowerShell command line with the full ngrok invocation, but no `ngrok.exe`
process create event appeared. The PowerShell `Start-Job` background job mechanism was
visible through EID 17 named pipe events and EID 11 file creation events for multiple
PowerShell runspace profiles. The `MpOAV.dll` (Defender AMSI provider) DLL load in
Sysmon EID 7 confirmed AMSI was engaged.

## What This Dataset Contains

The dataset spans approximately 9 seconds (17:42:27–17:42:36 UTC), longer than most tests
due to the `Start-Sleep -s 5` in the ngrok script. It contains 157 total events across
two channels.

**Security channel (16 events) — EIDs 4688, 4689, 4703:**

EID 4688 records capture the attack chain:

**Pre-flight `whoami.exe`:**
```
New Process Name: C:\Windows\System32\whoami.exe
Process Command Line: "C:\Windows\system32\whoami.exe"
Exit Status: 0x0
```

**Outer PowerShell with ngrok command:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "powershell.exe" & {C:\...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The `{C:\` prefix is consistent with the full ngrok invocation:
```powershell
{C:\Users\Public\ngrok\ngrok.exe config add-authtoken N/A | Out-Null
Start-Job -ScriptBlock { C:\Users\Public\ngrok\ngrok.exe tcp 3389 } | Out-Null
Start-Sleep -s 5
Stop-Job -Name Job1 | Out-Null}
```

**Background job `powershell.exe`:**
```
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: "C:\Windows\System32\Wi...
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Exit Status: 0xFFFFFFFF
```

The `"C:\Windows\System32\Wi...` prefix is consistent with `"C:\Windows\System32\
WindowsPowerShell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile`, the standard
`Start-Job` worker process invocation. The `0xFFFFFFFF` exit code (-1 as DWORD) indicates
the background job was terminated — consistent with `Stop-Job -Name Job1` killing the
ngrok tunnel process before it could establish a connection with the placeholder `N/A`
authtoken.

**Cleanup PowerShell:**
```
Process Command Line: "powershell.exe" & {Rem...
Exit Status: 0x0
```
Cleanup completed successfully.

**EID 4703** — SYSTEM token rights adjustment for the orchestrating `powershell.exe`.

**PowerShell channel (141 events) — EIDs 4104, 4103, 8193, 8194, 8195, 8196, 8197, 12039:**

This is the most diverse PowerShell event mix in this batch of tests.

**EID 4104 (117 events):** The majority are ART test framework boilerplate. The ngrok command
script block is present in the full corpus.

**EID 4103 (9 events):** `Set-ExecutionPolicy Bypass`, `Write-Host "DONE"`, and additional
module logging events from the Start-Job background job PowerShell process.

**EID 8193 (1 event), 8194 (1 event), 8195 (1 event):** PowerShell runspace creation
lifecycle: `Creating Runspace object`, `Creating RunspacePool object (MinRunspaces 1,
MaxRunspaces 1)`, `Opening RunspacePool`. These fire when `Start-Job` creates a new
PowerShell runspace for the background worker.

**EID 8196 (4 events), 8197 (4 events):** RunspacePool state transitions: `Opening`,
`Opened`, `Closing`, `Closed`. The full open-and-close cycle of the `Start-Job` runspace
appears here, covering both the ngrok start and the `Stop-Job` termination.

**EID 12039 (4 events):** PowerShell remoting / job transport events. These are generated
by the background job communication infrastructure.

The runspace lifecycle events (8193–8197, 12039) are a secondary indicator of `Start-Job`
usage in the attack chain — this specific event set distinguishes PowerShell background
job execution from foreground execution.

## What This Dataset Does Not Contain

**No `ngrok.exe` process creation event.** Security EID 4688 does not capture `ngrok.exe`
as a child process. The `0xFFFFFFFF` exit code from the background job `powershell.exe`
indicates the job was killed before completing, but it is unclear whether ngrok.exe was
launched and then killed, or whether the `N/A` authtoken caused ngrok to fail during
authentication before the process fully initialized. No process create evidence for the
ngrok binary appears in either channel.

**No Sysmon events.** The Sysmon channel is absent. The defended variant's 46 Sysmon events
included EID 1 with the full ngrok command line (`C:\Users\Public\ngrok\ngrok.exe config
add-authtoken N/A` and `ngrok.exe tcp 3389`), EID 7 with `MpOAV.dll` confirming AMSI
engagement, EID 11 for PowerShell runspace profile file creates, and EID 17 for named
pipe creation. Without Sysmon, the Security EID 4688 provides only the truncated command
line for the outer PowerShell process.

**No network events for ngrok tunnel establishment.** ngrok connects to `tunnel.us.ngrok.com`
(or similar regional endpoints) over HTTPS (443/tcp) to establish the tunnel. With Sysmon
absent and the `N/A` authtoken likely preventing successful authentication, no DNS query
or network connection for ngrok's cloud infrastructure appears.

**No confirmation of tunnel establishment.** The `0xFFFFFFFF` exit from the background job
process and the absence of network events suggest the ngrok tunnel was never established.
The placeholder `N/A` authtoken would be rejected by the ngrok authentication service.

## Assessment

The key difference between the defended and undefended datasets for this test is
significant: in the defended variant, Defender blocked `ngrok.exe` execution before the
background job ran. Here, the background job `powershell.exe` launched (EID 4688 shows it),
ran with `Start-Job`'s `-Version 5.1 -s -NoLogo -NoProfile` invocation, and exited with
`0xFFFFFFFF` after `Stop-Job` terminated it. The execution reached further into the attack
chain.

The PowerShell runspace lifecycle events (EIDs 8193–8197, 12039) are distinctive for
`Start-Job` usage and appear here in higher counts (4 each for 8196/8197/12039) reflecting
multiple runspace lifecycle cycles as the job worker started and stopped. These events are
rarely seen in defensive training datasets and represent real attack tooling infrastructure
at the PowerShell layer.

The 9-second collection window (driven by `Start-Sleep -s 5`) is longer than most test
windows in this dataset and demonstrates how a timing-aware test captures more background
OS activity — defenders building time-window correlation logic should account for
variations in attack pace.

## Detection Opportunities Present in This Data

**Security EID 4688 — `"powershell.exe" & {C:\Users\Public\ngrok\...`:** The combination
of `C:\Users\Public\` (world-writable path) and `ngrok.exe` in a PowerShell command block
is a high-confidence indicator. The staged binary location (`C:\Users\Public\ngrok\`) is
anomalous for legitimate ngrok developer use.

**Security EID 4688 — `Start-Job` background PowerShell (`-Version 5.1 -s -NoLogo
-NoProfile`):** This specific PowerShell invocation pattern is generated exclusively by
`Start-Job` / PowerShell background jobs. A `powershell.exe` with these exact flags spawned
by another `powershell.exe` running under SYSTEM indicates background job usage in an
attack chain.

**PowerShell EID 8193/8194/8195 — RunspacePool creation:** These three events firing in
sequence (runspace created → pool created → pool opened) indicate PowerShell background
job initialization. In a context where the parent session is conducting suspicious activity,
these runspace creation events indicate the adversary is using `Start-Job` to run a
component asynchronously — potentially to keep a C2 connection, polling loop, or tunnel
alive in the background while the foreground session continues other operations.

**PowerShell EID 8196/8197 — RunspacePool state transitions:** The full `Opening → Opened
→ Closing → Closed` sequence visible in this dataset shows the complete background job
lifecycle. In a live attack scenario, seeing `Opened` without a corresponding `Closing`
event would indicate a background job still running.

**Background job `powershell.exe` exit code `0xFFFFFFFF`:** This exit code (-1 as DWORD)
indicates the process was forcibly terminated, typically by `Stop-Job` or `Kill-Process`.
Combined with the preceding `Start-Job` infrastructure events, this pattern describes the
full ngrok tunnel start-and-stop cycle.
