# php2shell

Telemetry from an isolated exploit of the two PHP2SHELL vulnerabilities, [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) and [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619), in the pre-RINIT multipart parser of PHP. One vulnerable endpoint, `upload.php`, is attacked from a single host over about three hours. The multipart body is parsed during request startup, before application code runs, so three outcomes are reachable from the request alone:

- **Denial of service by memory exhaustion.** A large upload pushes the parser past the [`memory_limit`](https://www.php.net/manual/en/ini.core.php#ini.memory-limit) and crashes the request before any application code runs.
- **Command execution.** A crafted session combined with a [session upload-progress](https://www.php.net/manual/en/session.upload-progress.php) multipart runs a shell command as the account the web server runs under, which here is `www-data`, and the output comes back in the HTTP response.
- **Worker exhaustion.** A two-request sequence permanently hangs the Apache mod_php worker processes.

This dataset provides replayable logs for detection engineering and SOC-investigation training.

It includes the logs a PHP web deployment produces: the [nginx](https://nginx.org/) reverse-proxy access log, the [Apache](https://httpd.apache.org/) and [PHP-FPM](https://www.php.net/manual/en/install.fpm.php) server logs. It also includes a second deployment model, an inline [mitmproxy](https://mitmproxy.org/) reverse proxy in front of the app, which records full request and response bodies that the other logs do not. That is one possible way to run the service, not a requirement of the attack, and it makes the POST bodies and the command output in the response directly visible.

## What it is

- **277 events** across four sample log files, 2026-10-21 20:33:46 to 23:22:07 UTC (about 3 hours)
- **One target host**, `php2shell-target`, running an nginx reverse proxy and two PHP targets as Docker containers
- **Two target PHP deployments**: `p2s-fpm` (FPM, behind nginx) and `p2s-apache` (mod_php)
- **One attacker host**, 192.168.2.36 with user-agent `p2s-trigger/1.0`, plus local `curl` from the Docker host
- **One of the four files is an inline-proxy capture**: an optional mitmproxy reverse proxy records full request and response bodies, including the POST bodies and the command output, which the server and access logs do not carry
- **Ships a [MITRE Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/) file** ([`attack_flow.json`](attack_flow.json))

## Scenario

`upload.php` accepts multipart POSTs. On the vulnerable build, the multipart body is parsed during request startup, before application code runs, so three things are reachable from request shape alone.

**Memory-exhaustion probing.** Oversized multipart bodies drive the parser past [`memory_limit`](https://www.php.net/manual/en/ini.core.php#ini.memory-limit), and PHP fatals with `Allowed memory size ... exhausted ... in Unknown on line 0`. The error names no file or line because it happens before application code. On FPM the child exits code 70 and respawns; the request still returns a 200 whose body carries the leaked warning.

**Pre-RINIT command execution.** A crafted session file plus a [`PHP_SESSION_UPLOAD_PROGRESS`](https://www.php.net/manual/en/session.upload-progress.php) multipart makes the pre-RINIT session decode honor [`unserialize_callback_func`](https://www.php.net/manual/en/var.configuration.php#ini.unserialize-callback-func), reaching command execution as `www-data` (uid=33). The output returns inside the 200 response body. The working directory at request startup is the docroot. Class names are identifier-only, so this is a bare-token recon primitive; this capture holds `id` and `whoami`.

**Worker exhaustion.** On Apache mod_php a two-request sequence (an aborted upload-progress request, then a second upload-progress request) permanently hangs the worker, which never recovers. The access log goes silent for the hung request and the error log shows `AH00161 server reached MaxRequestWorkers`. FPM recovers on its own because an out-of-memory fatal exits and respawns the child, which is why, in our testing, we saw this only on Apache and not on FPM.

## Timeline

All times are original capture times on 2026-10-21 UTC. The Stage column matches the action IDs in [`attack_flow.json`](attack_flow.json).

| Stage | Time | Event | Evidence | ATT&CK |
|---|------|-------|----------|--------|
| S1 | 20:44:03 onward | Oversized multipart POSTs exhaust `memory_limit`; FPM children exit code 70 and respawn | [`php_fpm`](data/php_fpm.log.gz), [`apache_mod_php_vulnerable`](data/apache_mod_php_vulnerable.log.gz), [`nginx_access`](data/nginx_access.log.gz) | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) |
| S2 | 20:48:46 | Crafted session + upload-progress multipart reaches command execution as `www-data`; output in the 200 body | [`mitmproxy_capture`](data/mitmproxy_capture.log.gz), [`php_fpm`](data/php_fpm.log.gz) | [T1190](https://attack.mitre.org/techniques/T1190/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| S3 | 20:48:46 to 20:59:28 | Recon over the same channel: `id` returns `uid=33(www-data)`, `whoami` returns `www-data`, each in a 200 body | [`mitmproxy_capture`](data/mitmproxy_capture.log.gz) | [T1033](https://attack.mitre.org/techniques/T1033/) |
| S4 | 20:45:22, reproduced to 23:22 | Two-request sequence permanently hangs the Apache mod_php workers; the pool fills to `MaxRequestWorkers`, no access line | [`apache_mod_php_vulnerable`](data/apache_mod_php_vulnerable.log.gz) | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) |

## Data sources

| File | Sourcetype | Events | What it carries |
|------|-----------|--------|-----------------|
| [`nginx_access.log.gz`](data/nginx_access.log.gz) | `nginx:access` | 53 | Reverse-proxy combined access log. Every exploit request is a benign `POST /upload.php 200`; the only in-log signal is response-byte size off the endpoint baseline. |
| [`apache_mod_php_vulnerable.log.gz`](data/apache_mod_php_vulnerable.log.gz) | `php:apache` | 33 | Vulnerable mod_php container. The `in Unknown on line 0` fatals and the `MaxRequestWorkers` saturation signature. |
| [`php_fpm.log.gz`](data/php_fpm.log.gz) | `php:fpm` | 160 | The most detailed file: Request Startup warnings, child exit code 70, and the callback fingerprint `Function system() hasn't defined the class it was called for`. |
| [`mitmproxy_capture.log.gz`](data/mitmproxy_capture.log.gz) | `mitmproxy:capture` | 31 | Full request and response bodies, base64, one line per event. The RCE response body decodes to the `uid=33(www-data)` output. One line is about 8.6 MB (a 70 MB request). |

## Detection notes

These are the signals we saw in this run. A different stack, PHP build, or log configuration may show more or fewer.

- **The [reverse-proxy access log](data/nginx_access.log.gz) alone showed little.** The exploit requests are `POST /upload.php 200`. The main default-format signal we found is response-body size off the endpoint baseline. Default nginx logs do not carry the request body, request Content-Length, or response body.
- **The clearest stock signal we saw was the PHP fatal** `in Unknown on line 0` in the [Apache error log](data/apache_mod_php_vulnerable.log.gz), a fatal before application code.
- **FPM fingerprint of the RCE path.** Our successful exploit resulted in the warning `Function system() hasn't defined the class it was called for`. In this dataset that line sits in the [`php_fpm`](data/php_fpm.log.gz) file, which is the PHP-FPM error log. The worker emits the warning only when [`unserialize_callback_func`](https://www.php.net/manual/en/var.configuration.php#ini.unserialize-callback-func) is set, and that setting is what lets the exploit reach command execution. The warning reaches the FPM error log only when [`catch_workers_output`](https://www.php.net/manual/en/install.fpm.configuration.php) is also on, because that setting copies worker output into the log. Ubuntu's stock FPM pool turns `catch_workers_output` on. The official PHP Docker image leaves it off.
- **Command output and the session field** need response-body inspection or the [proxy capture](data/mitmproxy_capture.log.gz); none of the default pipelines we used ship either.
- **The hung mod_php workers** show up in [`apache_mod_php_vulnerable`](data/apache_mod_php_vulnerable.log.gz) as an access-log absence plus `AH00161 server reached MaxRequestWorkers`.

## Detection rules

Six sample [Sigma](https://sigmahq.io/) rules for the signals above live in [`rules/sigma/`](rules/sigma/), each matching a string present in these logs. Every rule passes `sigma check` and converts to Splunk, Loki, and Lucene. The FPM callback-fingerprint rule is the most specific to the vulnerability, and the memory-exhaustion rule is a corroborating signal that also fires on any startup OOM; one rule (the upload-progress request) needs request body capture, such as the inline-proxy deployment here. See the [Sigma rules README](rules/sigma/README.md) for the full list, the per-rule verification table, and field-mapping caveats.

## Replay

```
echolake echo --dataset local:./datasets/php2shell --output ./echoed --target-time now
```

Each log shifts in place by its native-format timestamp regex, so every line stays byte-for-byte identical apart from the shifted event time. The engine timestamp registry carries the `nginx:access`, `php:apache`, `php:fpm`, and `mitmproxy:capture` entries.

## Environment

Versions in this capture:

| Component | Version |
|-----------|---------|
| OS (host VM) | Ubuntu 22.04 |
| nginx (reverse proxy) | 1.18.0 |
| Apache (mod_php) | 2.4.69 |
| PHP (build under test) | 8.4.26 |
| mitmproxy (inline capture) | 12.2.3 |
| Fluent Bit (log shipper) | 5.1.5 |

## References

- CVE records: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- Fixed in PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35 (2026-10-21); PHP 8.1 and earlier get source-only backports
- Vendor analysis: [Wiz](https://www.wiz.io/blog/php2shell-php-rce), [Calif.io](https://calif.io/php2shell)
- [PHP release announcements](https://www.php.net/ChangeLog-8.php)

## License

[CC0 1.0 Universal (Public Domain Dedication)](../../LICENSE).
