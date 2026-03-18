# T1558.002-1: Silver Ticket — Crafting Active Directory silver tickets with mimikatz

## Technique Context

T1558.002 (Silver Ticket) involves forging a Kerberos Service Ticket (TGS) rather than a TGT. Unlike a golden ticket (which requires the KRBTGT hash and grants access to all services), a silver ticket requires only the service account's NTLM hash and grants forged access to the specific service that account manages. Silver tickets are stealthier — they are constructed entirely on the client, never touch the DC, and bypass KDC validation entirely. Mimikatz performs this with `kerberos::golden /service:<svc>` using an RC4 or AES key.

## What This Dataset Contains

The dataset spans six seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The test attempted to use mimikatz to forge a silver ticket. The PowerShell channel (EID 4103/4104) contains only ART test framework boilerplate — `Set-ExecutionPolicy -Bypass` in EID 4103, and exclusively `Set-StrictMode`/`PSMessageDetails`/`ErrorCategory_Message`/`OriginInfo` framework blocks in EID 4104. There is no mimikatz invocation or silver ticket command visible.

Sysmon events include:
- **EID 1** (Process Create): `whoami.exe` (T1033)
- **EID 7** (ImageLoad): DLL loads into PowerShell
- **EID 8** (CreateRemoteThread): PowerShell injecting a thread into another process (T1055) — the same pattern as T1558.001-1, with `<unknown process>` as the target image
- **EID 10** (ProcessAccess): Cross-process PowerShell access (T1055.001)
- **EID 11** (FileCreate): PowerShell transcript files
- **EID 17** (PipeCreate): Named PSHost pipes

Security events: EID 4688/4689/4703 for SYSTEM context process lifecycle only. No Kerberos events.

## What This Dataset Does Not Contain (and Why)

**No mimikatz command output or silver ticket forging logic in EID 4104.** Windows Defender with AMSI blocked the mimikatz payload before it could execute. The pattern mirrors T1558.001-1 exactly — AMSI interception prevents the script block from being written to logs.

**No Kerberos service ticket events.** A successfully forged silver ticket would be used directly against the target service without any DC interaction. Even in a successful run, EID 4769 on the DC would not be generated because the ticket bypasses the KDC. On the workstation, ticket injection would appear as an authentication event but only if Kerberos audit logging were active.

**No LSASS access events.** Mimikatz's silver ticket function (`kerberos::golden /service:`) can operate from a supplied hash parameter without reading LSASS — the ART test provides the hash explicitly.

**No Security EID 4768/4769.** The silver ticket technique's defining characteristic is the absence of DC-side Kerberos events — even in a successful execution, those events would not appear here.

## Assessment

Like T1558.001-1, this is a Defender-blocked attempt. The telemetry is nearly identical: Sysmon EID 8 (CreateRemoteThread to unknown process) is the primary indicator that mimikatz attempted reflective execution before being blocked. The dataset is valuable for understanding the pre-block artifact pattern common to mimikatz-based Kerberos attacks in a Defender-protected environment.

The silver ticket technique is notable for its inherent detection gap: even successful execution would not generate DC-side Kerberos events. Detection requires workstation-side monitoring of unusual service ticket use, LSASS memory access, or — as shown here — the process injection behavior of mimikatz itself.

## Detection Opportunities Present in This Data

- **EID 8 (Sysmon)**: CreateRemoteThread from `powershell.exe` to `<unknown process>` — consistent with reflective mimikatz injection. Identical pattern to T1558.001-1; a detection rule covering EID 8 with unknown target process would catch both golden and silver ticket attempts.
- **EID 10 (Sysmon)**: Cross-process PowerShell access (T1055.001) — detectable regardless of payload success.
- **Absence of LSASS in EID 10 target**: If mimikatz had successfully run and extracted a service account hash from LSASS, EID 10 would show `lsass.exe` as the target — its absence here (due to blocking) distinguishes pre-block from post-block scenarios.
- **AMSI telemetry**: Defender detection events would name the mimikatz signature — essential for attribution when EID 4104 contains only boilerplate.
- **DC-side gap awareness**: Architects should note that silver ticket use produces no DC-side Kerberos events. Detection for active silver ticket use requires behavioral analytics on service access patterns, PAC validation monitoring, or Kerberos event log anomalies on the service host rather than the DC.
