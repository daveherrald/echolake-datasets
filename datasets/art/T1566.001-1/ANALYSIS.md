# T1566.001-1: Spearphishing Attachment — Download Macro-Enabled Phishing Attachment

## Technique Context

T1566.001 (Spearphishing Attachment) covers adversary delivery of malicious files via email
as a means of initial access. The most enduring variant involves macro-enabled Office documents
(.xlsm, .docm) that execute code when the victim opens the file and enables macros. This test
simulates the delivery side: a PowerShell script downloads a macro-enabled Excel file
(`PhishingAttachment.xlsm`) from a public GitHub repository hosting the ART payload library.
The test does not open or execute the file — it only demonstrates the download step that would
precede a user interaction trigger.

## What This Dataset Contains

The dataset spans approximately 9 seconds (01:55:55–01:56:04 UTC) from ACME-WS02.

**PowerShell script block logging (4104)** captures the full test payload:

```
{$url = 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm}
```

This appears in both the outer (`& {...}`) and inner script block forms.

**PowerShell module logging (4103)** records `Invoke-WebRequest` with its bound parameters:
`-Uri "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm"`
and `-OutFile "C:\Windows\TEMP\PhishingAttachment.xlsm"`.

**Sysmon Event 22 (DNS Query)** captures two DNS lookups:
- `github.com` → `140.82.112.3`
- `raw.githubusercontent.com` → `185.199.108.133` (and three additional GitHub CDN IPs)

Both queries are attributed to PID 3356 with `<unknown process>` as the Image — this is a
known Sysmon limitation when DNS queries are made from a process that terminates before Sysmon
can resolve the image path.

**Sysmon Event 3 (Network Connection)** records an outbound TCP connection from
`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe` tagged
`technique_id=T1036,technique_name=Masquerading`. This is Windows Defender scanning the
downloaded file, not adversary activity. The source IP is `192.168.4.12` (ACME-WS02).

**Security 4688/4689** record process creation and termination for the PowerShell instances
and `whoami.exe` (the ART pre-flight check), all under `NT AUTHORITY\SYSTEM`.

## What This Dataset Does Not Contain (and Why)

**No file creation event for PhishingAttachment.xlsm.** Although `Invoke-WebRequest` writes
the file to `C:\Windows\TEMP\`, no Sysmon Event 11 appears for the .xlsm file itself. The
sysmon-modular configuration does not include an explicit rule capturing file writes to the
TEMP directory for arbitrary extensions, and the file write may have occurred in the brief
window before Sysmon logged it.

**No macro execution or Office process activity.** This test only downloads the file; it does
not open Word or Excel to execute the macro payload. The delivery step is represented, but the
execution consequence is not.

**No Security 4688 for the download process.** The download happens inside an existing
`powershell.exe` process (no new process is spawned for the download itself), so no 4688
is generated for the download action specifically.

**No Sysmon Event 3 from PowerShell itself.** Network connection telemetry from the
`Invoke-WebRequest` call is absent from Sysmon 3. This may be because the connection was made
over a .NET HTTP client that operates differently from a raw socket, or because the Sysmon
network connect rule did not fire for this process/port combination.

**No Defender detection events.** Windows Defender was active and scanned the downloaded file
(evidenced by the MsMpEng network connection), but no Application log Defender detection events
were collected. The .xlsm file is a known ART payload and may have been detected and quarantined,
but this is not visible in the bundled data.

## Assessment

The clearest signals are in PowerShell logging: the 4104 script block records the exact URL
and output path, and the 4103 module log records the `Invoke-WebRequest` parameter binding.
The DNS queries to `github.com` and `raw.githubusercontent.com` provide network-layer
corroboration. Together these three sources give a high-confidence picture of the download
event.

Most of the 42 PowerShell events are test framework boilerplate. Only three 4104/4103 events carry
the actual download content. The three Sysmon events (one network connection, two DNS queries)
are modest but meaningful. The ten Security events are process lifecycle records.

## Detection Opportunities Present in This Data

- **PowerShell 4104**: `Invoke-WebRequest` with an `-OutFile` path ending in `.xlsm`, `.xlsb`,
  `.docm`, or other macro-capable extensions, especially to `$env:TEMP`, is high-fidelity.

- **PowerShell 4103**: Explicit `Invoke-WebRequest` parameter binding logged with the URI and
  destination path, enabling exact URL match or domain-category lookup.

- **Sysmon 22 (DNS)**: Query to `raw.githubusercontent.com` or `github.com` from a process
  context associated with script execution is a useful enrichment signal.

- **Sysmon 3 (Network)**: MsMpEng outbound connection following a file write can indicate
  Defender scanning a newly arrived file, usable as a corroborating event in a detection chain.

- **Security 4688**: `powershell.exe` launched by SYSTEM from `C:\Windows\TEMP\` with a
  command line containing `Invoke-WebRequest` and a URL is anomalous on a managed workstation.
