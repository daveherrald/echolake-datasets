# T1090.003-2: Multi-hop Proxy — Tor Proxy Usage - Windows

## Technique Context

T1090.003 (Proxy: Multi-hop Proxy) covers adversary use of layered proxy networks to anonymize and obscure C2 traffic. Tor (The Onion Router) is the most widely known multi-hop proxy implementation, routing traffic through a series of encrypted relays so that no single node knows both the source and destination. Attackers use Tor on compromised hosts to maintain anonymous C2 channels, communicate with `.onion` hidden services hosting their infrastructure, and exfiltrate data through a path that is nearly impossible to trace back to their true origin.

Unlike Psiphon (which is primarily a censorship circumvention tool), Tor is the backbone of a significant portion of serious threat actor infrastructure. APT groups use Tor exits for C2 beaconing; ransomware operators host their negotiation portals as `.onion` services; initial access brokers sell access to hosts that already have persistent Tor-based backdoors. On a Windows host, Tor can be run as a standalone `tor.exe` binary — no installation or elevated privileges required.

This test demonstrates running the Tor binary (`C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe`) directly, wrapped in an `invoke-expression` + `cmd /c start powershell` chain to indirectly invoke the binary, sleeping 60 seconds to allow Tor to establish its circuits, then terminating the process.

## What This Dataset Contains

The dataset spans approximately two minutes (2026-03-14T23:37:41Z–23:39:43Z) on ACME-WS06.acme.local and contains 182 events across five channels.

**The core execution chain** is fully captured in Security EID 4688 and Sysmon EID 1. The Security channel shows the complete process tree:

1. `whoami.exe` — test framework environment check
2. PowerShell (PID 5500): `"powershell.exe" & {invoke-expression 'cmd /c start powershell -Command {cmd /c \"C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe\""}'` followed by `sleep -s 60` and `stop-process -name "tor"`
3. `cmd.exe` (from invoke-expression): `"C:\Windows\system32\cmd.exe" /c start powershell -encodedCommand YwBtAGQAIAAvAGMAIAAiAEMAOg...`
4. `powershell.exe` (launched with encoded command): `powershell -encodedCommand YwBtAGQAIAAvAGMAIAAiAEMAOg...`
5. `cmd.exe` (from decoded command): `"C:\Windows\system32\cmd.exe" /c C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe`
6. `whoami.exe` — post-execution test framework check

The encoded PowerShell command decodes to: `cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe"` — the actual Tor binary invocation. The multi-layer chain (`invoke-expression` → `cmd /c start powershell` → encoded command → `cmd /c tor.exe`) is characteristic of how real malware attempts to break parent-child process relationships to evade process tree analysis.

**The 60-second sleep** between launch and `stop-process` provides Tor time to bootstrap its circuits. In a real attack, this window would be when Tor establishes connectivity and the attacker's first C2 beacon would arrive.

**Sysmon EID 1** (7 events) captures `whoami.exe` (PID 6780) and the PowerShell child (PID 5500) with full hashes. The Tor invocation PowerShell is flagged `technique_id=T1059.001`.

**Sysmon EID 7** (33 events) records DLL loads across the multiple PowerShell processes created in the chain.

**Sysmon EID 10** (6 events) shows PowerShell processes accessing child processes with 0x1FFFFF access.

**Sysmon EID 11** (4 events) captures file creation events: PowerShell startup profile data files under `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\`.

**Sysmon EID 17** (4 events) records named pipe creation from PowerShell instances.

**PowerShell EID 4104** (116 events) and **EID 4103** (2 events) document the script block session. The key block contains the full `invoke-expression` chain visible as plaintext: `invoke-expression 'cmd /c start powershell -Command {cmd /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\tor\Tor\tor.exe"}'`. Even though the intermediate step uses a base64-encoded command, the original PowerShell script block containing the literal path to `tor.exe` is logged by EID 4104 before encoding is applied.

**Task Scheduler** (2 events, EIDs 102 and 201) records an unrelated scheduled task completing during the test window.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events appear. If `tor.exe` successfully launched and bootstrapped, you would expect to see network connections to Tor directory authorities and guard nodes on ports 9001 or 443. Their absence may indicate the binary did not reach the network connection phase, or that the 60-second window ended before the bootstrap completed in the test environment.

The `tor.exe` process creation itself does not appear as a Sysmon EID 1 event — consistent with the ProcessCreate filter gap for third-party binaries. You can infer its execution from the `cmd.exe` command line, but the Tor process's own PID, hash, and runtime attributes are not captured.

No `.onion` DNS queries appear (expected, since `.onion` addresses are resolved internally within the Tor network and would not generate standard DNS events on the host).

No Defender blocking or detection events exist — this is the clean-execution baseline with Defender disabled.

## Assessment

With Defender disabled, the Tor binary launched successfully (the 60-second sleep and subsequent `stop-process` confirm the test framework expected an active process to terminate). The dataset contains a complete, multi-layer process tree showing the indirect invocation of `tor.exe` — including the base64-encoded intermediate command whose decoded content is visible in the Security event log.

Compared to the defended variant (61 Sysmon, 19 Security, 58 PowerShell), the undefended dataset is slightly smaller in Sysmon (54 vs. 61) and Security (7 vs. 19) but larger in PowerShell (118 vs. 58). The defended run's additional Security and Sysmon events reflect Defender inspection activity; its lower PowerShell count reflects potential Defender interference with script block logging completeness. The undefended dataset provides a fuller view of the PowerShell execution context.

The critical detection data — the `tor.exe` path in the command line, the multi-hop invocation chain, and the 60-second sleep-then-terminate pattern — is fully preserved here.

## Detection Opportunities Present in This Data

**Process creation with `tor.exe` in command line**: Security EID 4688 (cmd.exe with `tor.exe` as argument) preserves the binary path. The string `tor.exe` from `ExternalPayloads\tor\Tor\tor.exe` in a process command line, particularly in a staging directory, is a high-confidence indicator.

**Base64-encoded PowerShell with decoded Tor path**: The PowerShell invocation with `-encodedCommand` that decodes to a `tor.exe` execution is visible in Security EID 4688. The encoded command itself (`YwBtAGQAIAAvAGMAIAAiAEMAOg...`) decodes to the Tor binary path. Detecting PowerShell `-encodedCommand` usage followed by `cmd.exe` with executable paths to `\tor\` is a useful behavioral chain.

**PowerShell EID 4104 script block with `invoke-expression` + `tor.exe`**: Before encoding is applied, the original script block containing the literal `tor.exe` path is captured in EID 4104. Searching script block content for `tor.exe` or the Psiphon/Tor staging path `ExternalPayloads\tor` provides a clear signal.

**Multi-hop PowerShell → cmd → PowerShell → cmd chain**: The process tree (4+ layers of PowerShell and cmd.exe nesting) is unusual for legitimate workstation activity and indicates an intentional attempt to obscure the final process's origin.

**Sleep followed by `stop-process -name "tor"`**: A PowerShell script that sleeps for 60 seconds and then terminates a process named `tor` is a behavioral pattern that would be distinctive in script block content analysis.
