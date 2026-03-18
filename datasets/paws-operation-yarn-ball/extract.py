#!/usr/bin/env python3
"""Extract PAWS March 18 data from Databricks bronze tables to echolake JSONL format."""

import gzip
import json
import os
import subprocess
import sys
import time

PROFILE = "dbc-1431d1cf-ddb8"
WAREHOUSE_ID = "304e02d8bba883aa"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# March 18 time window
TIME_FILTER = "time >= '2026-03-18' AND time < '2026-03-19'"

# PAWS host filter for wineventlog
PAWS_HOST_FILTER = "data:host::string LIKE 'PAWS%'"

# PAWS IP filter for zeek/proxy (catches .20-.26 and .200 C2, excludes ACME .10-.16)
PAWS_IP_FILTER = "CAST(data AS STRING) LIKE '%192.168.4.2%'"

# Wineventlog sources to split into separate files
WINEVENTLOG_SOURCES = [
    ("Microsoft-Windows-Sysmon/Operational", "sysmon"),
    ("Security", "security"),
    ("Microsoft-Windows-PowerShell/Operational", "powershell"),
    ("Microsoft-Windows-WMI-Activity/Operational", "wmi"),
    ("Microsoft-Windows-TaskScheduler/Operational", "taskscheduler"),
    ("System", "system"),
    ("Application", "application"),
]

# Batch size for LIMIT/OFFSET pagination (conservative to stay under 25MB inline limit)
BATCH_SIZE_SMALL = 5000   # wineventlog rows (~3-4KB each)
BATCH_SIZE_LARGE = 20000  # zeek/proxy rows (~0.5-1KB each)


def run_api(method, path, payload=None):
    """Execute Databricks API call and return parsed response."""
    cmd = ["databricks", "api", method, path, "--profile", PROFILE]
    if payload:
        cmd.extend(["--json", json.dumps(payload)])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  API ERROR: {result.stderr[:200]}", file=sys.stderr)
        return None
    return json.loads(result.stdout)


def submit_sql(sql):
    """Submit SQL statement and return response (may be PENDING)."""
    payload = {
        "warehouse_id": WAREHOUSE_ID,
        "statement": sql,
        "wait_timeout": "50s",
    }
    return run_api("post", "/api/2.0/sql/statements", payload)


def wait_for_result(response):
    """Wait for a SQL statement to complete. Returns final response or None."""
    if not response:
        return None
    state = response.get("status", {}).get("state")
    statement_id = response.get("statement_id")

    if state == "SUCCEEDED":
        return response

    if state in ("PENDING", "RUNNING"):
        print(f"  Polling (id: {statement_id})...")
        while state in ("PENDING", "RUNNING"):
            time.sleep(5)
            response = run_api("get", f"/api/2.0/sql/statements/{statement_id}")
            if not response:
                return None
            state = response.get("status", {}).get("state")
        if state == "SUCCEEDED":
            return response

    error = response.get("status", {}).get("error", {})
    msg = error.get("message", "") if error else ""
    print(f"  Query failed: {state} - {msg[:200]}", file=sys.stderr)
    return None


def fetch_chunk(statement_id, chunk_index):
    """Fetch a specific result chunk."""
    return run_api("get", f"/api/2.0/sql/statements/{statement_id}/result/chunks/{chunk_index}")


def write_response_data(response, f):
    """Write inline result data to file. Returns row count."""
    rows = 0
    data_array = response.get("result", {}).get("data_array", [])
    for row in data_array:
        if row[0] is not None:
            f.write(row[0] + "\n")
            rows += 1

    manifest = response.get("manifest", {})
    total_chunks = manifest.get("total_chunk_count", 1)
    statement_id = response.get("statement_id")

    if total_chunks > 1:
        for chunk_idx in range(1, total_chunks):
            chunk = fetch_chunk(statement_id, chunk_idx)
            if chunk and "data_array" in chunk:
                for row in chunk["data_array"]:
                    if row[0] is not None:
                        f.write(row[0] + "\n")
                        rows += 1
    return rows


def extract_batched(base_sql, output_file, description, batch_size):
    """Extract data using LIMIT/OFFSET batching. Returns row count."""
    print(f"\n{'='*60}")
    print(f"Extracting (batched, size={batch_size}): {description}")
    print(f"  Output: {output_file}")

    filepath = os.path.join(OUTPUT_DIR, output_file)
    total_rows = 0
    offset = 0
    batch_num = 0

    with gzip.open(filepath, "wt", encoding="utf-8") as f:
        while True:
            batch_num += 1
            sql = f"{base_sql} LIMIT {batch_size} OFFSET {offset}"

            response = wait_for_result(submit_sql(sql))
            if not response:
                print(f"  Batch {batch_num} failed at offset {offset}", file=sys.stderr)
                break

            rows_in_batch = write_response_data(response, f)
            total_rows += rows_in_batch

            print(f"  Batch {batch_num}: +{rows_in_batch:,} rows (total: {total_rows:,})")

            if rows_in_batch < batch_size:
                break  # Last batch
            offset += batch_size

    if total_rows == 0:
        os.remove(filepath)
        print(f"  Skipped (0 rows)")
        return 0

    file_size = os.path.getsize(filepath)
    print(f"  Done: {total_rows:,} rows, {file_size / 1024 / 1024:.1f} MB")
    return total_rows


def extract_inline(sql, output_file, description):
    """Extract data using single inline query. Returns row count."""
    print(f"\n{'='*60}")
    print(f"Extracting: {description}")
    print(f"  Output: {output_file}")

    response = wait_for_result(submit_sql(sql))
    if not response:
        return 0

    filepath = os.path.join(OUTPUT_DIR, output_file)
    with gzip.open(filepath, "wt", encoding="utf-8") as f:
        total_rows = write_response_data(response, f)

    if total_rows == 0:
        os.remove(filepath)
        print(f"  Skipped (0 rows)")
        return 0

    file_size = os.path.getsize(filepath)
    print(f"  Done: {total_rows:,} rows, {file_size / 1024 / 1024:.1f} MB")
    return total_rows


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    counts = {}
    start_time = time.time()

    # === WINEVENTLOG (split by source) ===
    # Large sources use batched extraction; small ones use inline
    large_sources = {"Microsoft-Windows-Sysmon/Operational", "Security",
                     "Microsoft-Windows-WMI-Activity/Operational"}

    for source_name, file_prefix in WINEVENTLOG_SOURCES:
        base_sql = (
            f"SELECT CAST(data AS STRING) "
            f"FROM sec_lakehouse.bronze.wineventlog "
            f"WHERE {PAWS_HOST_FILTER} "
            f"AND data:source::string = '{source_name}' "
            f"AND {TIME_FILTER} "
            f"ORDER BY time"
        )
        if source_name in large_sources:
            count = extract_batched(base_sql, f"{file_prefix}.jsonl.gz",
                                    f"wineventlog / {source_name}", BATCH_SIZE_SMALL)
        else:
            count = extract_inline(base_sql, f"{file_prefix}.jsonl.gz",
                                   f"wineventlog / {source_name}")
        counts[file_prefix] = count

    # Catch any other wineventlog sources
    known_sources = "', '".join(s for s, _ in WINEVENTLOG_SOURCES)
    sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.wineventlog "
        f"WHERE {PAWS_HOST_FILTER} "
        f"AND data:source::string NOT IN ('{known_sources}') "
        f"AND {TIME_FILTER} "
        f"ORDER BY time"
    )
    count = extract_inline(sql, "wineventlog_other.jsonl.gz", "wineventlog / other sources")
    if count > 0:
        counts["wineventlog_other"] = count

    # === PROXYLOG ===
    sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.proxylog "
        f"WHERE {PAWS_IP_FILTER} "
        f"AND {TIME_FILTER} "
        f"ORDER BY time"
    )
    counts["proxylog"] = extract_inline(sql, "proxylog.jsonl.gz", "proxylog (PAWS IPs)")

    # === ZEEK CONN (large - use batched) ===
    base_sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.zeek_conn "
        f"WHERE {PAWS_IP_FILTER} "
        f"AND {TIME_FILTER} "
        f"ORDER BY time"
    )
    counts["zeek_conn"] = extract_batched(base_sql, "zeek_conn.jsonl.gz",
                                          "zeek_conn (PAWS IPs)", BATCH_SIZE_LARGE)

    # === ZEEK DNS ===
    sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.zeek_dns "
        f"WHERE {PAWS_IP_FILTER} "
        f"AND {TIME_FILTER} "
        f"ORDER BY time"
    )
    counts["zeek_dns"] = extract_inline(sql, "zeek_dns.jsonl.gz", "zeek_dns (PAWS IPs)")

    # === ZEEK HTTP ===
    base_sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.zeek_http "
        f"WHERE {PAWS_IP_FILTER} "
        f"AND {TIME_FILTER} "
        f"ORDER BY time"
    )
    counts["zeek_http"] = extract_inline(base_sql, "zeek_http.jsonl.gz", "zeek_http (PAWS IPs)")

    # === SMTP EMAIL ===
    sql = (
        f"SELECT CAST(data AS STRING) "
        f"FROM sec_lakehouse.bronze.smtp_email "
        f"WHERE {TIME_FILTER} "
        f"ORDER BY time"
    )
    counts["smtp_email"] = extract_inline(sql, "smtp_email.jsonl.gz", "smtp_email")

    # === SUMMARY ===
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print("EXTRACTION SUMMARY")
    print(f"{'='*60}")
    total = 0
    for name, count in counts.items():
        if count > 0:
            print(f"  {name:30s} {count:>10,} rows")
            total += count
    print(f"  {'TOTAL':30s} {total:>10,} rows")
    print(f"  Elapsed: {elapsed/60:.1f} minutes")
    print(f"\n  Output directory: {OUTPUT_DIR}")

    # List output files with sizes
    print(f"\n  Files:")
    total_size = 0
    for fn in sorted(os.listdir(OUTPUT_DIR)):
        fpath = os.path.join(OUTPUT_DIR, fn)
        size = os.path.getsize(fpath)
        total_size += size
        print(f"    {fn:40s} {size / 1024 / 1024:>8.1f} MB")
    print(f"    {'TOTAL':40s} {total_size / 1024 / 1024:>8.1f} MB")

    # Write counts to a JSON file for use by manifest generator
    counts_file = os.path.join(os.path.dirname(OUTPUT_DIR), "extraction_counts.json")
    with open(counts_file, "w") as f:
        json.dump(counts, f, indent=2)
    print(f"\n  Counts saved to: {counts_file}")


if __name__ == "__main__":
    main()
