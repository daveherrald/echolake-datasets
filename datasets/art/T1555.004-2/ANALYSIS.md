# T1555.004-2: Windows Credential Manager — WinPwn - Loot local Credentials - Invoke-WCMDump

## Technique Context

T1555.004 (Windows Credential Manager) includes using purpose-built credential dumping tools against the Windows Vault. WinPwn is a PowerShell-based post-exploitation framework; its `Invoke-WCMDump` function reads Windows Credential Manager entries programmatically using the CredEnumerate Win32 API rather than the `VaultCmd.exe` LOLBin. This represents a more invasive and typically more capable approach than T1555.004-1, capable of recovering decrypted credential values.

## What This Dataset Contains

The dataset spans six seconds on 2026-03-14 on ACME-WS02 (Windows 11 Enterprise, domain acme.local). The PowerShell channel contains 41 events — all EID 4103 and 4104 entries. The EID 4104 script block events consist entirely of PowerShell framework boilerplate (`Set-StrictMode`, `PSMessageDetails`, `OriginInfo`, `ErrorCategory_Message`) — the actual `Invoke-WCMDump` invocation script block is absent from the dataset.

This is a consequence of Windows Defender blocking the technique. The AMSI-enabled environment detected the WinPwn/WCMDump payload before the script block with the credential-dumping logic was written to the PowerShell EID 4104 event log. What remains is the test framework setup overhead.

Sysmon events include:
- **EID 1** (Process Create): `whoami.exe` (T1033) only — no additional processes were spawned by the blocked tool
- **EID 7** (ImageLoad): Standard PowerShell DLL loads
- **EID 8** (CreateRemoteThread): PowerShell creating a remote thread in another process (T1055) — this occurred during the test framework execution, not from WCMDump
- **EID 10** (ProcessAccess): Cross-process PowerShell access (T1055.001)
- **EID 11** (FileCreate): PowerShell transcript files
- **EID 17** (PipeCreate): Named PSHost pipes

Security events: EID 4688/4689/4703 for SYSTEM context process lifecycle.

## What This Dataset Does Not Contain (and Why)

**No Invoke-WCMDump script block in EID 4104.** Windows Defender with AMSI (enabled, signature version 1.445.536.0) blocked the payload. AMSI intercepts the script content before PowerShell logs a full script block for it. The 39 EID 4104 events are all framework-level boilerplate from the ART test framework infrastructure.

**No credential enumeration API calls.** Since the payload was blocked, CredEnumerate was never called and there are no Vault access artifacts.

**No Security EID 4688 for WCMDump-spawned processes.** The tool was blocked before any credential-reading activity occurred.

**No AMSI block event in this dataset.** Windows Defender's detection events appear in the Application event log channel, which was not included in the bundled dataset for this test.

## Assessment

This dataset documents a Defender-blocked attempt with pre-block telemetry only. The value is in demonstrating what an attacker would see from the logging perspective when AMSI blocks execution: process creation for the test framework's PowerShell instance, DLL loads, and named pipe creation — but none of the actual credential-dumping artifact. The EID 8 (CreateRemoteThread) is notable and warrants attention, as it indicates the test framework itself performed thread injection during test setup, generating a T1055 indicator independent of the WCMDump payload.

## Detection Opportunities Present in This Data

- **EID 8 (Sysmon)**: CreateRemoteThread from `powershell.exe` to another process — even in a blocked scenario, this is an indicator of injection behavior in the test framework chain.
- **EID 10 (Sysmon)**: Cross-process PowerShell access (T1055.001) is present and detectable regardless of whether the payload succeeded.
- **EID 4688 (Security)**: `whoami.exe` spawned from PowerShell under SYSTEM is the pre-execution reconnaissance indicator consistent across T1555.004 tests.
- **Absence as signal**: If defenders are monitoring for EID 4104 blocks containing `Invoke-WCMDump` or `WCMDump` and see only boilerplate followed by abrupt process termination, this pattern may indicate AMSI blocked a payload.
- **AMSI telemetry**: Deploying Defender ATP or forwarding Application event log channel 8011 (Windows Defender detection) would surface the specific WinPwn/WCMDump detection that is invisible in this dataset.
