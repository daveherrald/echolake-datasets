# T1187-3: Forced Authentication — Trigger an authenticated RPC call to a target server with no Sign flag set

## Technique Context

Forced Authentication (T1187) via `rpcping.exe` uses a legitimate Microsoft built-in utility to trigger an authenticated RPC connection to a target server using NTLM authentication, without setting the packet-signing flag. The signing flag absence makes the authentication attempt potentially vulnerable to interception and relay attacks. Because `rpcping.exe` ships with Windows and is signed by Microsoft, this technique exploits a "living off the land" binary (LOLBin) that security tools may not flag by default. An attacker positioned to capture the resulting NTLM challenge-response (e.g., via Responder or similar tooling) could relay it for lateral movement or crack it offline. The specific invocation `rpcping -s 127.0.0.1 -e 9997 /a connect /u NTLM 1>$Null` targets localhost port 9997 (where no RPC server is typically listening), meaning the authentication attempt will fail — but the generated NTLM negotiation traffic is still theoretically capturable.

## What This Dataset Contains

With Windows Defender disabled, this dataset captures the complete `rpcping.exe` execution from ACME-WS06.acme.local.

**Full process execution chain in Security EID 4688:** Five process creation events are present:

1. PowerShell parent (PID 18036) spawns `whoami.exe` — pre-execution identity check
2. PowerShell parent spawns child PowerShell (PID 16348) with `"powershell.exe" & {rpcping -s 127.0.0.1 -e 9997 /a connect /u NTLM 1>$Null}` — the technique invocation
3. Child PowerShell spawns `"C:\Windows\system32\RpcPing.exe" -s 127.0.0.1 -e 9997 /a connect /u NTLM` — the actual LOLBin execution
4. PowerShell parent spawns `whoami.exe` — post-execution identity check
5. PowerShell parent spawns child PowerShell for cleanup (`"powershell.exe" & {}`)

**Sysmon EID 1:** The Sysmon samples confirm the child PowerShell creation. RpcPing.exe itself appears in the full Sysmon data (the dataset description references `RpcPing.exe` process GUID `{9dc7570a-7d19-69b4-035a-000000001000}`), though it may not be in the 20-event sample.

**PowerShell EID 4104:** 108 events including the technique block `{rpcping -s 127.0.0.1 -e 9997 /a connect /u NTLM 1>$Null}` — the exact command with output suppression (`1>$Null`) is captured in the script block log.

**Process exit code:** RpcPing.exe exits with `0x6BA` (error 1722, "The RPC server is unavailable"), confirming the connection to `127.0.0.1:9997` failed as expected — no service was listening.

**Sysmon DLL loading:** 25 EID 7 events reflect .NET CLR and Defender DLL loading across the PowerShell processes.

**File artifacts:** Sysmon EID 11 records three file events, including `C:\Windows\Temp\null` (created by cmd.exe redirecting output to `nul`) confirming the `2>null` redirection in the cleanup command was executed.

Compared to the defended dataset (28 Sysmon, 15 Security, 31 PowerShell), this undefended run has more events (41 Sysmon, 5 Security, 111 PowerShell), which is unusual — typically undefended runs produce fewer events than defended ones because Defender's blocking generates additional system noise. Here, the higher Sysmon count (41 vs. 28) may reflect the undefended run completing additional phases of the test framework that were blocked in the defended run.

## What This Dataset Does Not Contain

**Network connection events (Sysmon EID 3):** The RPC connection attempt to `127.0.0.1:9997` does not appear as a Sysmon EID 3 event. Sysmon-modular configurations typically filter out localhost connections. If the target were a remote IP, a network connection event would be expected.

**NTLM authentication events:** Because the target port had no listening service, the NTLM handshake did not complete. No Security EID 4648 (explicit credential logon), EID 4624 (logon), or EID 4625 (failed logon) events appear.

**DNS resolution:** The target is `127.0.0.1` (a direct IP), so no DNS query is expected or present.

**Credential capture evidence:** Whether any NTLM material was generated and potentially capturable by a man-in-the-middle listener is not determinable from this dataset — the connection failed before completing the full handshake.

## Assessment

This dataset captures the full execution of a LOLBin-based forced authentication technique. The most reliable detection signal is Security EID 4688 showing `RpcPing.exe` with the exact flags `/a connect /u NTLM` — the `/a connect` (authentication level: connect, no packet signing) and `/u NTLM` (force NTLM authentication) combination is the specific configuration that makes this technique threatening.

`rpcping.exe` is a legitimate utility but rarely used in normal workstation operation. Any occurrence of `RpcPing.exe` in Security EID 4688 or Sysmon EID 1 on a workstation should be investigated. The combination of `/a connect /u NTLM` with a non-domain target IP (or an unusual IP like `10.0.0.x`) would be a high-confidence indicator.

The PowerShell EID 4104 script block log provides a second detection layer that captures the technique even if process creation auditing is not enabled: `rpcping -s [IP] -e [port] /a connect /u NTLM` is a distinctive string pattern.

Compared to the defended variant (which showed the same process chain with lower event counts), this dataset provides the identical process creation telemetry. The technique behavior is deterministic regardless of Defender state because `rpcping.exe` is a system binary that Defender does not flag.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** `RpcPing.exe` with arguments `-s [IP] -e [port] /a connect /u NTLM` — the `/a connect /u NTLM` combination specifically disables signing and forces NTLM, which is the attack-relevant configuration
- **Process tree:** PowerShell spawning a child PowerShell which spawns `rpcping.exe` is anomalous; normal RpcPing usage would be invoked directly from cmd.exe or a user session, not from a SYSTEM-context PowerShell chain
- **PowerShell EID 4104:** `rpcping -s 127.0.0.1 -e 9997 /a connect /u NTLM 1>$Null` in script block logs — output suppression (`1>$Null`) is a behavioral indicator of deliberately hidden execution
- **Process lineage:** `RpcPing.exe` spawned from PowerShell running as SYSTEM (`IntegrityLevel: System`, `LogonId: 0x3E7`) is highly anomalous on a domain workstation
- **Sysmon EID 11:** `C:\Windows\Temp\null` file creation from cmd.exe confirms the cleanup redirect to `nul` was executed; this artifact pattern is associated with ART test framework test teardown
