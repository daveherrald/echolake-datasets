# BOTSv1 - Boss of the SOC v1

## Overview

Boss of the SOC v1 is a sample security dataset and CTF platform containing evidence from realistic security incidents captured in 2016.

## Dataset Details

- **Created:** 2016
- **Authors:** Ryan Kovar, David Herrald, James Brodsky (Splunk)
- **License:** CC0-1.0 (Public Domain)
- **Size:** ~11GB compressed CSV files
- **Sourcetypes:** 22
- **Format:** CSV files (ready to use with EchoLake)

## Data Sources

### Windows Logs
- WinEventLog:Application
- WinEventLog:Security
- WinEventLog:System
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Network Logs (Fortinet Fortigate)
- fortigate_event
- fortigate_traffic
- fortigate_utm

### Web Server
- IIS access logs

### Vulnerability Scans
- Nessus scan results

### Network Protocols (Splunk Stream)
- DHCP, DNS, HTTP, ICMP, IP
- LDAP, MAPI, SIP, SMB, SNMP, TCP

### Security Tools
- Suricata IDS alerts

### Windows Registry
- WinRegistry

## Downloading the Data

Run the download script to fetch all CSV files:

```bash
cd bots-datasets/botsv1
./download_data.sh
```

This will download 22 CSV files (~11GB+ compressed) to the `data/` directory.

Or download individual files from:
https://botsdataset.s3.amazonaws.com/botsv1/

## Using with EchoLake

Once downloaded and extracted:

```bash
# Extract CSV files
cd data
gunzip *.csv.gz

# Replay with EchoLake
echolake replay \
  --dataset local:./bots-datasets/botsv1 \
  --output ./replayed-botsv1 \
  --target-time now-1h
```

## CSV Files

1. botsv1.WinEventLog%3AApplication.csv.gz
2. botsv1.WinEventLog%3ASecurity.csv.gz
3. botsv1.WinEventLog%3ASystem.csv.gz
4. botsv1.XmlWinEventLog%3AMicrosoft-Windows-Sysmon-Operational.csv.gz
5. botsv1.fgt_event.csv.gz
6. botsv1.fgt_traffic.csv.gz
7. botsv1.fgt_utm.csv.gz
8. botsv1.iis.csv.gz
9. botsv1.nessus%3Ascan.csv.gz
10. botsv1.stream%3Adhcp.csv.gz
11. botsv1.stream%3Adns.csv.gz
12. botsv1.stream%3Ahttp.csv.gz
13. botsv1.stream%3Aicmp.csv.gz
14. botsv1.stream%3Aip.csv.gz
15. botsv1.stream%3Aldap.csv.gz
16. botsv1.stream%3Amapi.csv.gz
17. botsv1.stream%3Asip.csv.gz
18. botsv1.stream%3Asmb.csv.gz
19. botsv1.stream%3Asnmp.csv.gz
20. botsv1.stream%3Atcp.csv.gz
21. botsv1.suricata.csv.gz
22. botsv1.winregistry.csv.gz

## Content Warning

⚠️ This dataset contains evidence from actual security incidents and may include profanity, slang, or offensive terminology.

## Source

- **GitHub:** https://github.com/splunk/botsv1
- **Download:** https://botsdataset.s3.amazonaws.com/botsv1/
