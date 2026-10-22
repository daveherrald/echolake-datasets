# php2shell detection rules (Sigma)

Sample [Sigma](https://sigmahq.io/) rules for the signals in this dataset. They are
starting points for detection engineering against the PHP2SHELL vulnerabilities
(CVE-2026-109618, CVE-2026-109619), not tuned production content. Each one matches a
string that is present in the dataset's logs.

| Rule | Detects | Log | Level | ATT&CK |
|------|---------|-----|-------|--------|
| [memory_exhaustion_fatal](php2shell_memory_exhaustion_fatal.yml) | Pre-RINIT OOM fatal from an oversized multipart body (`in Unknown on line 0`); corroborating, fires on any startup OOM | [`apache_mod_php_vulnerable`](../data/apache_mod_php_vulnerable.log.gz), [`php_fpm`](../data/php_fpm.log.gz) | low | T1499.004 |
| [rce_unserialize_callback](php2shell_rce_unserialize_callback.yml) | FPM fingerprint of the `unserialize_callback_func` command-execution path | [`php_fpm`](../data/php_fpm.log.gz) | high | T1190, T1059.004 |
| [apache_worker_exhaustion](php2shell_apache_worker_exhaustion.yml) | Apache `MaxRequestWorkers` saturation from the hung-worker sequence | [`apache_mod_php_vulnerable`](../data/apache_mod_php_vulnerable.log.gz) | medium | T1499.004 |
| [fpm_child_abnormal_exit](php2shell_fpm_child_abnormal_exit.yml) | PHP-FPM children exiting code 70 (corroborates the probes) | [`php_fpm`](../data/php_fpm.log.gz) | low | T1499.004 |
| [session_upload_progress_exploit](php2shell_session_upload_progress_exploit.yml) | `PHP_SESSION_UPLOAD_PROGRESS` in a POST body to the endpoint | [`mitmproxy_capture`](../data/mitmproxy_capture.log.gz) | high | T1190 |

## Notes

- **One rule needs body capture.** `session_upload_progress_exploit` reads the request
  body, which a default access log does not carry. It fires against the inline-proxy
  deployment in this dataset, or any reverse proxy or WAF that logs bodies.
- **Field names are the parsed representation.** `message` is the parsed log line;
  `request_body`, `response_body`, and `cs-method` are the proxy's fields. Map them to
  your own pipeline's field names before deploying.
- **These are samples.** Tune thresholds and false positives for your environment. The
  FPM callback-fingerprint rule is the most specific to the vulnerability; the
  memory-exhaustion rule is a corroborating signal that also fires on any startup OOM;
  the body-inspection rule is the highest fidelity where body logging exists.
