# php2shell rule conversions

Generated with sigma-cli; see `pipelines/php2shell_logsources.yml` for the Splunk/Lucene source mapping (Loki needs none). Replace the source paths with your own index or sourcetype.

## Apache mod_php Worker Pool Exhaustion
```splunk
source IN ("/var/log/apache2/error.log", "/var/log/httpd/error_log") message="*server reached MaxRequestWorkers*"
```
```logql
{job=~".+"} | logfmt | message=~`(?i).*server\ reached\ MaxRequestWorkers.*`
```
```lucene
(source:(\/var\/log\/apache2\/error.log OR \/var\/log\/httpd\/error_log)) AND message:*server\ reached\ MaxRequestWorkers*
```

## PHP-FPM Child Abnormal Exit Code 70
```splunk
source IN ("/var/log/php*-fpm.log", "/var/log/php-fpm/*.log") message="*[pool www] child*" message="*exited with code 70*"
```
```logql
{job=~".+"} | logfmt | message=~`(?i).*\[pool\ www\]\ child.*` and message=~`(?i).*exited\ with\ code\ 70.*`
```
```lucene
(source:(\/var\/log\/php*\-fpm.log OR \/var\/log\/php\-fpm\/*.log)) AND (message:*\[pool\ www\]\ child* AND message:*exited\ with\ code\ 70*)
```

## PHP Pre-RINIT Multipart Memory-Exhaustion Fatal
```splunk
source IN ("/var/log/php*-fpm.log", "/var/log/nginx/error.log", "/var/log/apache2/error.log", "/var/log/httpd/error_log") message="*Allowed memory size of*" message="*in Unknown on line 0*"
```
```logql
{job=~".+"} | logfmt | message=~`(?i).*Allowed\ memory\ size\ of.*` and message=~`(?i).*in\ Unknown\ on\ line\ 0.*`
```
```lucene
(source:(\/var\/log\/php*\-fpm.log OR \/var\/log\/nginx\/error.log OR \/var\/log\/apache2\/error.log OR \/var\/log\/httpd\/error_log)) AND (message:*Allowed\ memory\ size\ of* AND message:*in\ Unknown\ on\ line\ 0*)
```

## PHP Pre-RINIT unserialize_callback_func Command Execution
```splunk
source IN ("/var/log/php*-fpm.log", "/var/log/php-fpm/*.log") message="*hasn't defined the class it was called for*"
```
```logql
{job=~".+"} | logfmt | message=~`(?i).*hasn't\ defined\ the\ class\ it\ was\ called\ for.*`
```
```lucene
(source:(\/var\/log\/php*\-fpm.log OR \/var\/log\/php\-fpm\/*.log)) AND message:*hasn't\ defined\ the\ class\ it\ was\ called\ for*
```

## PHP Session Decode Failure After Memory-Exhaustion Arm
```splunk
source IN ("/var/log/php*-fpm.log", "/var/log/php-fpm/*.log") message="*Failed to decode session object*"
```
```logql
{job=~".+"} | logfmt | message=~`(?i).*Failed\ to\ decode\ session\ object.*`
```
```lucene
(source:(\/var\/log\/php*\-fpm.log OR \/var\/log\/php\-fpm\/*.log)) AND message:*Failed\ to\ decode\ session\ object*
```

## PHP Session Upload-Progress Multipart to Upload Endpoint
```splunk
source="/var/log/mitmproxy/capture.log" "cs-method"="POST" request_body="*PHP_SESSION_UPLOAD_PROGRESS*"
```
```logql
{job=~".+"} | logfmt | cs_method=~`(?i)^POST$` and request_body=~`(?i).*PHP_SESSION_UPLOAD_PROGRESS.*`
```
```lucene
source:\/var\/log\/mitmproxy\/capture.log AND (cs-method:POST AND request_body:*PHP_SESSION_UPLOAD_PROGRESS*)
```

