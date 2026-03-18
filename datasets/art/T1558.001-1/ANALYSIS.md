# T1558.001-1: Golden Ticket — Crafting Active Directory golden tickets with mimikatz

## Technique Context

T1558.001 (Golden Ticket) is a Kerberos persistence and lateral movement technique where an attacker forges a Ticket Granting Ticket (TGT) using the KRBTGT account's NTLM hash. Because the KRBTGT hash is used to sign all TGTs issued by a domain controller, possession of this hash enables creation of arbitrary TGTs for any user or group, valid for any duration. Golden tickets provide domain persistence that survives most account password resets. Mimikatz performs this via its `kerberos::golden` module.

## What This Dataset Contains

The dataset spans five seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The test attempted to run mimikatz to craft a golden ticket. The PowerShell channel (EID 4103/4104) contains only ART test framework boilerplate — `Set-ExecutionPolicy -Bypass` in EID 4103, and repetitive `Set-StrictMode`/`PSMessageDetails`/`ErrorCategory_Message`/`OriginInfo` framework blocks in EID 4104. One EID 4104 fragment records a partial `Set-NetTCPSetting` module export — likely from PowerShell's networking module auto-loading. There is no mimikatz invocation visible in script block logging.

Sysmon events provide the most informative content:
- **EID 1** (Process Create): `whoami.exe` (T1033) — test framework pre-test enumeration
- **EID 3** (Network connection): `MpDefenderCoreService.exe` outbound connection (Defender telemetry)
- **EID 7** (ImageLoad): DLLs loaded into PowerShell — standard .NET/PowerShell loads
- **EID 8** (CreateRemoteThread): PowerShell creating a remote thread in an `<unknown process>` at address `0x00007FF7A9A94EB0`, tagged T1055. The target process GUID is populated but the image name is `<unknown process>` — indicative of a short-lived or reflectively loaded process. This is the most significant technique-relevant event in the dataset.
- **EID 10** (ProcessAccess): Cross-process PowerShell access (T1055.001)
- **EID 11** (FileCreate): PowerShell transcript files
- **EID 17** (PipeCreate): Named PSHost pipes

Security events: only EID 4688/4689/4703 — no Kerberos authentication events.

## What This Dataset Does Not Contain (and Why)

**No mimikatz command output or `kerberos::golden` invocation in logs.** Windows Defender with AMSI blocked the mimikatz payload before it could log a meaningful script block or execute the Kerberos golden ticket function. AMSI intercepts the content before EID 4104 logs it.

**No EID 4768/4769 (Kerberos TGT/service ticket requests).** A successfully crafted golden ticket would be used from memory without triggering a DC-side Kerberos request — by design, that is the technique's evasion property. Additionally, the test was blocked before a ticket could be forged or used.

**No LSASS access events (Sysmon EID 10 to lsass.exe).** Mimikatz's `kerberos::golden` can forge tickets without reading LSASS if the KRBTGT hash is supplied as a parameter — which ART does in this test using a hardcoded value. No LSASS read was needed or attempted.

**No Security 4624 logon events.** No golden ticket was successfully injected into the session.

## Assessment

This is a Defender-blocked attempt. The primary forensic evidence is Sysmon EID 8 — a CreateRemoteThread from PowerShell to an unknown process — which occurred during the blocked execution. This suggests mimikatz was partially instantiated (possibly reflectively loaded into a short-lived process) before Defender terminated it. The lack of any meaningful script block content confirms AMSI intercepted the payload. Defenders relying only on EID 4104 would see nothing; EID 8 is the observable indicator here.

## Detection Opportunities Present in This Data

- **EID 8 (Sysmon)**: CreateRemoteThread from `powershell.exe` to `<unknown process>` — the unknown target image is characteristic of reflective DLL injection or in-memory process execution used by mimikatz. This is high-confidence suspicious.
- **EID 10 (Sysmon)**: Cross-process PowerShell access tagged T1055.001 — present even when the payload was blocked.
- **EID 4688 (Security)**: `powershell.exe` under SYSTEM with no meaningful child processes shortly after is consistent with a blocked execution — process lifecycle without credential activity.
- **AMSI telemetry**: Windows Defender detection events (Application log channel) would surface the specific mimikatz signature match, which is invisible in this dataset.
- **DC-side Kerberos**: In a successful golden ticket scenario, detection shifts to the domain controller — anomalous TGTs with unusual lifetime, PAC forging indicators, or Kerberos encryption type mismatches. None of those signals are present here because the attack was blocked at the workstation.
