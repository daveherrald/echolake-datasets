# php2shell detection rules (Sigma)

Sample [Sigma](https://sigmahq.io/) rules for the signals in this dataset. They are
starting points for detection engineering against the PHP2SHELL vulnerabilities
(CVE-2026-109618, CVE-2026-109619), not tuned production content. Each one matches a
string present in this dataset's logs, passes `sigma check`, and converts to Splunk,
Loki, and Lucene (see [`conversions.md`](conversions.md)).

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [memory_exhaustion_fatal](php2shell_memory_exhaustion_fatal.yml) | Pre-RINIT OOM fatal from an oversized multipart body (`in Unknown on line 0`); corroborating, fires on any startup OOM | [`apache_mod_php_vulnerable`](../data/apache_mod_php_vulnerable.log.gz), [`php_fpm`](../data/php_fpm.log.gz) | low | T1499.004 |
| [rce_unserialize_callback](php2shell_rce_unserialize_callback.yml) | FPM fingerprint of the `unserialize_callback_func` command-execution path | [`php_fpm`](../data/php_fpm.log.gz) | high | T1190, T1059.004 |
| [session_decode_failure](php2shell_session_decode_failure.yml) | `Failed to decode session object` after the memory-exhaustion arm | [`php_fpm`](../data/php_fpm.log.gz) | medium | T1190 |
| [apache_worker_exhaustion](php2shell_apache_worker_exhaustion.yml) | Apache `MaxRequestWorkers` saturation from the hung-worker sequence | [`apache_mod_php_vulnerable`](../data/apache_mod_php_vulnerable.log.gz) | medium | T1499.004 |
| [fpm_child_abnormal_exit](php2shell_fpm_child_abnormal_exit.yml) | PHP-FPM children exiting code 70 (corroborates the probes) | [`php_fpm`](../data/php_fpm.log.gz) | low | T1499.004 |
| [session_upload_progress_exploit](php2shell_session_upload_progress_exploit.yml) | `PHP_SESSION_UPLOAD_PROGRESS` in a POST body to the endpoint | [`mitmproxy_capture`](../data/mitmproxy_capture.log.gz) | high | T1190 |

## Verification

Every rule was checked with `sigma check` (0 errors, 0 issues), counted against the
dataset, and converted to all three backends. The match count is the number of
dataset lines (or capture request bodies) that satisfy the rule's full condition.

| Rule | `sigma check` | Dataset matches | Splunk | Loki | Lucene |
|------|:---:|:---:|:---:|:---:|:---:|
| memory_exhaustion_fatal | pass | 36 | yes | yes | yes |
| rce_unserialize_callback | pass | 8 | yes | yes | yes |
| session_decode_failure | pass | 9 | yes | yes | yes |
| apache_worker_exhaustion | pass | 3 | yes | yes | yes |
| fpm_child_abnormal_exit | pass | 29 | yes | yes | yes |
| session_upload_progress_exploit | pass | 6 | yes | yes | yes |

Converted queries are in [`conversions.md`](conversions.md). The Splunk and Lucene
conversions use [`pipelines/php2shell_logsources.yml`](pipelines/php2shell_logsources.yml),
which maps the php, apache, and proxy logsources to `source=` filters; Loki needs no
pipeline. Replace the source paths with your own index or sourcetype.

Toolchain used for verification:

| Tool | Version |
|------|---------|
| sigma-cli | 3.1.0 |
| pySigma | 1.5.1 |
| pysigma-backend-splunk | 2.1.0 |
| pysigma-backend-elasticsearch (Lucene) | 2.1.1 |
| pysigma-backend-loki | 0.15.1 |

## Notes

- **One rule needs body capture.** `session_upload_progress_exploit` reads the request
  body, which a default access log does not carry. It fires against the inline-proxy
  deployment in this dataset, or any reverse proxy or WAF that logs bodies.
- **Field names are the parsed representation.** `message` is the parsed log line;
  `request_body` and `cs-method` are the proxy's fields. Map them to your own pipeline's
  field names before deploying.
- **These are samples.** Tune thresholds and false positives for your environment. The
  FPM callback-fingerprint rule is the most specific to the vulnerability; the
  memory-exhaustion rule is a corroborating signal that also fires on any startup OOM;
  the body-inspection rule is the highest fidelity where body logging exists.
- **Logsources are non-standard.** `product: php / service: php-fpm`, `product: php /
  category: application`, and `category: proxy` are not SigmaHQ-standard taxonomy; the
  keyword rules convert cleanly regardless, and the pipeline maps them to real files.
