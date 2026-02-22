# BOTSv1 - Boss of the SOC v1

## Overview

Boss of the SOC v1 is a sample security dataset and CTF platform containing evidence from realistic security incidents captured in 2016. Two attacks by a fictitious hacktivist group called po1s0n1vy targeting Wayne Corp.

## Dataset Details

- **Created:** 2016
- **Authors:** Ryan Kovar, David Herrald, James Brodsky (Splunk)
- **License:** CC0-1.0 (Public Domain)
- **Size:** ~1.8 GB compressed CSV
- **Sourcetypes:** 22
- **Format:** CSV (Splunk export: _serial, _time, source, sourcetype, host, index, splunk_server, _raw)

## Data Sources (22 sourcetypes)

### Windows Logs
- WinEventLog:Application
- WinEventLog:Security
- WinEventLog:System
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Network (Fortinet Fortigate)
- fortigate_event
- fortigate_traffic
- fortigate_utm

### Web Server
- iis

### Vulnerability Scans
- nessus:scan

### Network Protocols (Splunk Stream)
- stream:dhcp, stream:dns, stream:http, stream:icmp, stream:ip
- stream:ldap, stream:mapi, stream:sip, stream:smb, stream:snmp, stream:tcp

### Security Tools
- suricata

### Windows Registry
- WinRegistry

## Using with EchoLake

```bash
echolake replay \
  --dataset local:bots/botsv1 \
  --output ./replayed \
  --path-template "{sourcetype}/{filename}" \
  --target-time now-1h
```

## Data Source

CSV files downloaded from `https://s3.amazonaws.com/botsdataset/botsv1/csv-by-sourcetype/`

## Source

- **GitHub:** https://github.com/splunk/botsv1
