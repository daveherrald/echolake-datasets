# T1614-1: System Location Discovery — Get geolocation info through IP-Lookup services using curl Windows

## Technique Context

T1614 (System Location Discovery) covers adversary attempts to determine the geographic location of a target system. Location data has multiple uses in post-compromise tradecraft: determining whether the target is in a specific country (some malware avoids attacking certain regions), understanding local time zones for scheduling operations, confirming the host is not a sandbox or honeypot (many sandboxes use predictable IP ranges), or tailoring lure content to the apparent locale.

This test uses the native Windows `curl.exe` binary — shipped with Windows 10 and later — to query `https://ipinfo.io/`, a public IP geolocation service that returns JSON containing the querying host's public IP address, city, region, country, ISP, and other metadata. The `-k` flag disables TLS certificate verification. This is a living-off-the-land (LotL) technique: it uses a Microsoft-signed system binary to exfiltrate location data to an external service.

## What This Dataset Contains

The dataset captures 123 events across three log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103), Security (15 events: 9 EID 4689, 5 EID 4688, 1 EID 4703), and Sysmon (1 event: EID 22). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The curl execution chain is fully captured in Security EID 4688.** PowerShell spawned cmd.exe:

```
"cmd.exe" /c C:\Windows\System32\Curl.exe -k https://ipinfo.io/
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

cmd.exe then spawned curl.exe:

```
New Process Name: C:\Windows\System32\curl.exe
Process Command Line: C:\Windows\System32\Curl.exe -k https://ipinfo.io/
Creator Process Name: C:\Windows\System32\cmd.exe
```

Both processes exited at `0x0`, confirming curl ran successfully and received a response.

**Sysmon EID 22 (DNS query) confirms the network lookup:**

```
QueryName: ipinfo.io
QueryStatus: 0
QueryResults: ::ffff:34.117.59.81
Image: <unknown process>
ProcessId: 17644
```

The DNS query resolved `ipinfo.io` to `34.117.59.81` (a Google Cloud IP — ipinfo.io uses Google Cloud for hosting). `QueryStatus: 0` indicates the lookup succeeded. The `Image: <unknown process>` field indicates the Sysmon EID 22 was generated for a process that was no longer running when Sysmon attempted to correlate it, a timing artifact common with short-lived processes like curl.

The cleanup cmd.exe process (`"cmd.exe" /c` with an empty body) represents the ART cleanup stub for a test with no persistent artifacts.

Security EID 4703 records the parent PowerShell (PID 0x39a8) receiving elevated privileges including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeSecurityPrivilege` — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon EID 3 (Network Connection).** Despite the DNS query being captured in EID 22, there is no corresponding Sysmon EID 3 recording the TCP connection to `34.117.59.81:443`. This is a collection gap — either the network connection event was not generated within the Sysmon rule set or it was not included in the sample window. The HTTPS connection to ipinfo.io is confirmed indirectly by the successful DNS resolution and the curl process exiting at `0x0`.

**No content of the geolocation response.** The JSON returned by `ipinfo.io` (containing public IP, city, country, ISP, etc.) is not captured anywhere in this dataset. You can confirm the query was made and likely succeeded, but the actual data exfiltrated is not visible.

**No TLS certificate validation events.** The `-k` flag bypasses certificate checks; no certificate-related events are generated.

## Assessment

The defended variant recorded 21 Sysmon, 12 Security, and 34 PowerShell events. Sysmon in that run would have included EID 3 (Network Connection) showing curl.exe connecting to ipinfo.io, and likely EID 1 (Process Create) with image hashes. The undefended run produced 1 Sysmon (EID 22 only), 15 Security, and 107 PowerShell events.

The undefended dataset adds two events relative to the defended comparison: EID 4688 for the cmd.exe process (capturing the full curl command line) and the EID 22 DNS record. In the defended variant, Defender may have intercepted the curl execution or the connection; here, both the process runs and the DNS lookup succeed.

The EID 22 DNS record for `ipinfo.io` from SYSTEM-context execution is a particularly clean indicator — `ipinfo.io` is a geolocation API, not a Windows system component or typical enterprise service.

## Detection Opportunities Present in This Data

**EID 4688 — curl.exe with `-k` flag querying an IP geolocation API from a PowerShell/cmd.exe chain running as SYSTEM.** The combination of `curl.exe -k https://ipinfo.io/` is a high-confidence indicator. `ipinfo.io`, `ip-api.com`, `ipgeolocation.io`, and similar services have no place in the normal process execution of a Windows enterprise workstation. The `-k` flag (skip TLS verification) is itself an indicator of scripted, non-interactive usage.

**Sysmon EID 22 — DNS query for `ipinfo.io` from any process.** A DNS lookup for an IP geolocation API from a workstation — especially from a process running as SYSTEM — should be rare to nonexistent in a managed enterprise environment. IP geolocation APIs are used by attackers for host profiling and by researchers and malware analysts, not by typical endpoint software.

**EID 4688 — cmd.exe spawned by PowerShell (SYSTEM) to invoke a system binary with an external HTTPS URL.** PowerShell using cmd.exe as a launcher for `curl.exe` with a hardcoded external API URL is an unusual pattern. Legitimate administrative scripts that need to query external services typically use PowerShell's `Invoke-WebRequest` or `Invoke-RestMethod` directly, not a cmd.exe wrapper around `curl.exe`.

**Process lineage: PowerShell → cmd.exe → curl.exe** with an external API endpoint is a detectable execution pattern for LotL-based recon. Baselining which processes are allowed to initiate outbound HTTPS connections — and from which parent chains — would surface this immediately.
