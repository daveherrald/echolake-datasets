# Operation Black Start rule conversions

Generated with sigma-cli; see `pipelines/currentis_logsources.yml` for the Splunk/Lucene source mapping (Loki needs none). Replace the source paths with your own index or sourcetype.

## Outbound Connection to Known C2 Indicator
```splunk
source IN ("zeek_conn", "/opt/zeek/logs/current/conn.log") id.resp_h="121.43.243.13"
```
```logql
{job=~".+"} | json | id_resp_h=~`(?i)^121\.43\.243\.13$`
```
```lucene
(source:(zeek_conn OR \/opt\/zeek\/logs\/current\/conn.log)) AND id.resp_h:121.43.243.13
```
