# cloud-data-exfiltration rule conversions

Generated with sigma-cli. The Splunk and Lucene queries use
[`pipelines/cloudexfil_logsources.yml`](pipelines/cloudexfil_logsources.yml) to map each
logsource to its `source=` sourcetype; Loki needs no pipeline. Replace the sources with
your own index or sourcetype.

## GitHub Secret-Scanning Alert for a Leaked SSH Private Key

`cloudexfil_github_leaked_ssh_key_alert.yml`

**Splunk**
```
source="github:audit" action="secret_scanning_alert.create" secret_type="ssh_private_key"
```

**Loki**
```
{job=~".+"} | logfmt | action=~`(?i)^secret_scanning_alert\.create$` and secret_type=~`(?i)^ssh_private_key$`
```

**Lucene**
```
source:github\:audit AND (action:secret_scanning_alert.create AND secret_type:ssh_private_key)
```

## SSH Activity From the Intruder Source Address

`cloudexfil_ssh_login_from_intruder_ip.yml`

**Splunk**
```
source="linux_secure:fluentbit" message="*54.193.215.120*"
```

**Loki**
```
{job=~".+"} | logfmt | message=~`(?i).*54\.193\.215\.120.*`
```

**Lucene**
```
source:linux_secure\:fluentbit AND message:*54.193.215.120*
```

## EC2 Instance Metadata (IMDS) Access From a Shell Command

`cloudexfil_imdsv2_credential_theft.yml`

**Splunk**
```
source="crowdstrike:fdr" CommandLine="*169.254.169.254*"
```

**Loki**
```
{job=~".+"} | logfmt | CommandLine=~`(?i).*169\.254\.169\.254.*`
```

**Lucene**
```
source:crowdstrike\:fdr AND CommandLine:*169.254.169.254*
```

## Mass Read of the ML Training-Data S3 Bucket

`cloudexfil_s3_training_bucket_mass_read.yml`

**Splunk**
```
source="aws:cloudtrail" eventName IN ("GetObject", "ListObjects", "HeadObject") requestParameters.bucketName="jn-model-training-data-5233"
```

**Loki**
```
{job=~".+"} | logfmt | (eventName=~`(?i)^GetObject$` or eventName=~`(?i)^ListObjects$` or eventName=~`(?i)^HeadObject$`) and requestParameters_bucketName=~`(?i)^jn\-model\-training\-data\-5233$`
```

**Lucene**
```
source:aws\:cloudtrail AND ((eventName:(GetObject OR ListObjects OR HeadObject)) AND requestParameters.bucketName:jn\-model\-training\-data\-5233)
```

## SFTP Server Bulk File Read

`cloudexfil_sftp_bulk_file_read.yml`

**Splunk**
```
source="linux_secure:fluentbit" message="*sftp-server[*" message="*flags READ*"
```

**Loki**
```
{job=~".+"} | logfmt | message=~`(?i).*sftp\-server\[.*` and message=~`(?i).*flags\ READ.*`
```

**Lucene**
```
source:linux_secure\:fluentbit AND (message:*sftp\-server\[* AND message:*flags\ READ*)
```

## VPC Flow Egress to the Intruder Address

`cloudexfil_vpcflow_exfil_to_intruder_ip.yml`

**Splunk**
```
source="aws:vpcflow:json" dstaddr="54.193.215.120"
```

**Loki**
```
{job=~".+"} | logfmt | dstaddr=~`(?i)^54\.193\.215\.120$`
```

**Lucene**
```
source:aws\:vpcflow\:json AND dstaddr:54.193.215.120
```

## GitHub Secret-Scanning Alert Resolved as wont_fix

`cloudexfil_github_secret_alert_resolved_wontfix.yml`

**Splunk**
```
source="github:audit" action="secret_scanning_alert.resolved" resolution="wont_fix"
```

**Loki**
```
{job=~".+"} | logfmt | action=~`(?i)^secret_scanning_alert\.resolved$` and resolution=~`(?i)^wont_fix$`
```

**Lucene**
```
source:github\:audit AND (action:secret_scanning_alert.resolved AND resolution:wont_fix)
```
