#!/usr/bin/env python3
"""Acquire auditable SHA-256 checksums for every BOTS manifest reference.

The output remains compatible with ``generate_splunk_metadata.py`` through its
top-level ``files`` mapping. The parallel ``objects`` mapping records the S3
metadata and acquisition method used for each digest.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
BOTS_ROOT = REPO_ROOT / "datasets" / "bots"
OUTPUT_PATH = REPO_ROOT / "scripts" / "data" / "bots_sha256.json"
BUCKET = "echolake-datasets"
KEY_RE = re.compile(r"^native/bots[^/]*/.+$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SCHEMA_VERSION = 1
CHUNK_SIZE = 8 * 1024 * 1024

HEAD_CHECKSUM_METHOD = "head_object_full_sha256"
STREAM_METHOD = "get_object_stream_sha256"
HEAD_ONLY_METHOD = "head_object_unresolved"
ACQUISITION_METHODS = {
    HEAD_CHECKSUM_METHOD,
    STREAM_METHOD,
    HEAD_ONLY_METHOD,
}
AUDIT_FIELDS = {
    "sha256",
    "size",
    "etag",
    "last_modified",
    "version_id",
    "checksum_type",
    "acquisition_method",
}


class AcquisitionError(RuntimeError):
    """Raised when an input or S3 response cannot be trusted."""


def botocore_error_message(error: Exception) -> str | None:
    """Return a concise message for botocore failures without requiring boto3 offline."""

    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return None
    if isinstance(error, ClientError):
        details = error.response.get("Error") or {}
        code = str(details.get("Code") or "ClientError")
        message = str(details.get("Message") or error)
        return f"{code}: {message}"
    if isinstance(error, BotoCoreError):
        return str(error)
    return None


def call_s3(
    operation: str,
    uri: str,
    callback: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run one S3 API operation and preserve its object context on failure."""

    try:
        return callback()
    except Exception as error:
        message = botocore_error_message(error)
        if message is not None:
            raise AcquisitionError(
                f"S3 {operation} failed for {uri}: {message}"
            ) from error
        raise


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AcquisitionError(f"Expected a YAML mapping in {path}")
    return value


def manifest_uris() -> list[str]:
    """Return the sorted, globally unique native BOTS S3 references."""

    manifest_paths = sorted(BOTS_ROOT.glob("*/dataset.yaml"))
    if not manifest_paths:
        raise AcquisitionError(f"No BOTS manifests found under {BOTS_ROOT}")

    owners: dict[str, Path] = {}
    for manifest_path in manifest_paths:
        manifest = load_yaml(manifest_path)
        references = (manifest.get("files") or {}).get("references")
        if not isinstance(references, list) or not references:
            raise AcquisitionError(f"No files.references entries in {manifest_path}")
        for index, reference in enumerate(references):
            if not isinstance(reference, dict) or not isinstance(reference.get("uri"), str):
                raise AcquisitionError(
                    f"Invalid files.references[{index}] URI in {manifest_path}"
                )
            uri = reference["uri"]
            parsed = urlsplit(uri)
            key = parsed.path.lstrip("/")
            if (
                parsed.scheme != "s3"
                or parsed.netloc != BUCKET
                or parsed.query
                or parsed.fragment
                or not KEY_RE.fullmatch(key)
            ):
                raise AcquisitionError(
                    f"Unsupported BOTS reference in {manifest_path}: {uri}"
                )
            if uri in owners:
                raise AcquisitionError(
                    f"Duplicate BOTS reference {uri} in {owners[uri]} and {manifest_path}"
                )
            owners[uri] = manifest_path
    return sorted(owners)


def empty_checkpoint(uri_count: int) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "algorithm": "sha256",
        "request_payer": "requester",
        "manifest_uri_count": uri_count,
        "files": {},
        "objects": {},
    }


def validate_audit_record(uri: str, record: Any) -> None:
    if not isinstance(record, dict):
        raise AcquisitionError(f"Audit record is not a mapping for {uri}")
    if set(record) != AUDIT_FIELDS:
        missing = sorted(AUDIT_FIELDS - set(record))
        extra = sorted(set(record) - AUDIT_FIELDS)
        raise AcquisitionError(
            f"Audit fields differ for {uri}: missing={missing}, extra={extra}"
        )
    digest = record["sha256"]
    if digest is not None and (
        not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest)
    ):
        raise AcquisitionError(f"Invalid audit SHA-256 for {uri}")
    if not isinstance(record["size"], int) or record["size"] < 0:
        raise AcquisitionError(f"Invalid object size for {uri}")
    if not isinstance(record["etag"], str) or not record["etag"]:
        raise AcquisitionError(f"Missing ETag for {uri}")
    if not isinstance(record["last_modified"], str) or not record["last_modified"]:
        raise AcquisitionError(f"Missing LastModified for {uri}")
    if record["version_id"] is not None and not isinstance(record["version_id"], str):
        raise AcquisitionError(f"Invalid VersionId for {uri}")
    if record["checksum_type"] is not None and not isinstance(
        record["checksum_type"], str
    ):
        raise AcquisitionError(f"Invalid ChecksumType for {uri}")
    method = record["acquisition_method"]
    if method not in ACQUISITION_METHODS:
        raise AcquisitionError(f"Invalid acquisition method for {uri}: {method}")
    if method == HEAD_ONLY_METHOD and digest is not None:
        raise AcquisitionError(f"HEAD-only record unexpectedly has a digest for {uri}")
    if method != HEAD_ONLY_METHOD and digest is None:
        raise AcquisitionError(f"Resolved audit record lacks a digest for {uri}")


def validate_checkpoint(
    checkpoint: Any,
    expected_uris: Iterable[str],
    *,
    require_complete: bool,
) -> None:
    if not isinstance(checkpoint, dict):
        raise AcquisitionError("Checksum checkpoint is not a JSON object")
    expected = set(expected_uris)
    expected_header = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": "sha256",
        "request_payer": "requester",
        "manifest_uri_count": len(expected),
    }
    for field, value in expected_header.items():
        if checkpoint.get(field) != value:
            raise AcquisitionError(
                f"Checkpoint {field} must be {value!r}, got {checkpoint.get(field)!r}"
            )
    files = checkpoint.get("files")
    objects = checkpoint.get("objects")
    if not isinstance(files, dict) or not isinstance(objects, dict):
        raise AcquisitionError("Checkpoint files and objects must be JSON objects")
    if not set(files).issubset(expected):
        raise AcquisitionError(
            f"Checkpoint has unexpected file URIs: {sorted(set(files) - expected)}"
        )
    if not set(objects).issubset(expected):
        raise AcquisitionError(
            f"Checkpoint has unexpected audit URIs: {sorted(set(objects) - expected)}"
        )
    for uri, digest in files.items():
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise AcquisitionError(f"Invalid checkpoint SHA-256 for {uri}")
        if uri not in objects:
            raise AcquisitionError(f"Checkpoint digest lacks audit metadata for {uri}")
    for uri, record in objects.items():
        validate_audit_record(uri, record)
        digest = record["sha256"]
        if digest is None and uri in files:
            raise AcquisitionError(f"Unresolved audit record has a file digest for {uri}")
        if digest is not None and files.get(uri) != digest:
            raise AcquisitionError(f"Digest and audit metadata disagree for {uri}")
    if require_complete:
        if set(files) != expected or set(objects) != expected:
            missing_files = sorted(expected - set(files))
            missing_objects = sorted(expected - set(objects))
            raise AcquisitionError(
                "Checkpoint is incomplete: "
                f"missing_digests={len(missing_files)}, "
                f"missing_audit_records={len(missing_objects)}"
            )


def load_checkpoint(path: Path, uris: list[str]) -> dict[str, Any]:
    if not path.exists():
        return empty_checkpoint(len(uris))
    try:
        checkpoint = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcquisitionError(f"Cannot read checkpoint {path}: {error}") from error
    validate_checkpoint(checkpoint, uris, require_complete=False)
    return checkpoint


def write_checkpoint(path: Path, checkpoint: dict[str, Any], uris: list[str]) -> None:
    """Validate and atomically replace the checkpoint in its destination directory."""

    validate_checkpoint(checkpoint, uris, require_complete=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(checkpoint, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def split_s3_uri(uri: str) -> tuple[str, str]:
    parsed = urlsplit(uri)
    return parsed.netloc, parsed.path.lstrip("/")


def timestamp_text(value: Any, *, uri: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str) and value:
        return value
    raise AcquisitionError(f"Missing or invalid LastModified for {uri}")


def response_metadata(response: dict[str, Any], *, uri: str) -> dict[str, Any]:
    size = response.get("ContentLength")
    etag = response.get("ETag")
    if not isinstance(size, int) or size < 0:
        raise AcquisitionError(f"Missing or invalid ContentLength for {uri}")
    if not isinstance(etag, str) or not etag:
        raise AcquisitionError(f"Missing or invalid ETag for {uri}")
    version_id = response.get("VersionId")
    checksum_type = response.get("ChecksumType")
    if version_id is not None and not isinstance(version_id, str):
        raise AcquisitionError(f"Invalid VersionId in S3 response for {uri}")
    if checksum_type is not None and not isinstance(checksum_type, str):
        raise AcquisitionError(f"Invalid ChecksumType in S3 response for {uri}")
    return {
        "size": size,
        "etag": etag,
        "last_modified": timestamp_text(response.get("LastModified"), uri=uri),
        "version_id": version_id,
        "checksum_type": checksum_type,
    }


def full_object_checksum(response: dict[str, Any], *, uri: str) -> str | None:
    encoded = response.get("ChecksumSHA256")
    checksum_type = response.get("ChecksumType")
    if encoded is None or checksum_type != "FULL_OBJECT":
        return None
    if not isinstance(encoded, str):
        raise AcquisitionError(f"Invalid ChecksumSHA256 type for {uri}")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AcquisitionError(f"Invalid base64 ChecksumSHA256 for {uri}") from error
    if len(raw) != hashlib.sha256().digest_size:
        raise AcquisitionError(f"ChecksumSHA256 is not 32 bytes for {uri}")
    return raw.hex()


def assert_same_object(
    head_metadata: dict[str, Any],
    get_metadata: dict[str, Any],
    *,
    uri: str,
) -> None:
    for field in ("size", "etag", "last_modified", "version_id"):
        if head_metadata[field] != get_metadata[field]:
            raise AcquisitionError(
                f"S3 object changed between HEAD and GET for {uri}: {field} differs"
            )


def stream_sha256(client: Any, uri: str, head: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    bucket, key = split_s3_uri(uri)
    head_metadata = response_metadata(head, uri=uri)
    request: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "RequestPayer": "requester",
        "ChecksumMode": "ENABLED",
    }
    version_id = head_metadata["version_id"]
    if isinstance(version_id, str) and version_id:
        request["VersionId"] = version_id
    else:
        request["IfMatch"] = head_metadata["etag"]
    response = call_s3(
        "GetObject",
        uri,
        lambda: client.get_object(**request),
    )
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise AcquisitionError(f"S3 GetObject returned no readable body for {uri}")
    digest = hashlib.sha256()
    bytes_read = 0
    try:
        try:
            while True:
                chunk = body.read(CHUNK_SIZE)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise AcquisitionError(f"S3 body returned non-byte data for {uri}")
                digest.update(chunk)
                bytes_read += len(chunk)
        except Exception as error:
            message = botocore_error_message(error)
            if message is not None:
                raise AcquisitionError(
                    f"S3 GetObject body read failed for {uri}: {message}"
                ) from error
            raise
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    metadata = response_metadata(response, uri=uri)
    if bytes_read != metadata["size"]:
        raise AcquisitionError(
            f"Downloaded byte count differs for {uri}: "
            f"expected={metadata['size']}, actual={bytes_read}"
        )
    assert_same_object(head_metadata, metadata, uri=uri)
    actual_digest = digest.hexdigest()
    response_digest = full_object_checksum(response, uri=uri)
    if response_digest is not None and response_digest != actual_digest:
        raise AcquisitionError(
            f"S3 FULL_OBJECT checksum differs from streamed bytes for {uri}"
        )
    return actual_digest, metadata


def audit_record(
    metadata: dict[str, Any],
    *,
    digest: str | None,
    method: str,
) -> dict[str, Any]:
    return {
        "sha256": digest,
        "size": metadata["size"],
        "etag": metadata["etag"],
        "last_modified": metadata["last_modified"],
        "version_id": metadata["version_id"],
        "checksum_type": metadata["checksum_type"],
        "acquisition_method": method,
    }


def acquire_one(client: Any, uri: str, *, head_only: bool) -> dict[str, Any]:
    bucket, key = split_s3_uri(uri)
    head = call_s3(
        "HeadObject",
        uri,
        lambda: client.head_object(
            Bucket=bucket,
            Key=key,
            RequestPayer="requester",
            ChecksumMode="ENABLED",
        ),
    )
    head_metadata = response_metadata(head, uri=uri)
    digest = full_object_checksum(head, uri=uri)
    if digest is not None:
        return audit_record(
            head_metadata,
            digest=digest,
            method=HEAD_CHECKSUM_METHOD,
        )
    if head_only:
        return audit_record(
            head_metadata,
            digest=None,
            method=HEAD_ONLY_METHOD,
        )
    digest, get_metadata = stream_sha256(client, uri, head)
    return audit_record(get_metadata, digest=digest, method=STREAM_METHOD)


def make_s3_client(profile: str | None) -> Any:
    try:
        import boto3
    except ImportError as error:
        raise AcquisitionError(
            "boto3 is required for acquisition; install it or use --validate-only"
        ) from error
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session.client("s3")
    except Exception as error:
        message = botocore_error_message(error)
        if message is not None:
            raise AcquisitionError(f"Cannot initialize the S3 client: {message}") from error
        raise


def acquire(
    uris: list[str],
    checkpoint: dict[str, Any],
    *,
    output: Path,
    profile: str | None,
    limit: int | None,
    head_only: bool,
) -> int:
    completed = checkpoint["objects"] if head_only else checkpoint["files"]
    pending = [uri for uri in uris if uri not in completed]
    selected = pending if limit is None else pending[:limit]
    client = make_s3_client(profile) if selected else None
    try:
        for index, uri in enumerate(selected, start=1):
            record = acquire_one(client, uri, head_only=head_only)
            checkpoint["objects"][uri] = record
            digest = record["sha256"]
            if digest is None:
                checkpoint["files"].pop(uri, None)
            else:
                checkpoint["files"][uri] = digest
            write_checkpoint(output, checkpoint, uris)
            status = "resolved" if digest is not None else "HEAD only"
            print(f"[{index}/{len(selected)}] {status}: {uri}")
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()

    unresolved = [uri for uri in uris if uri not in checkpoint["files"]]
    if unresolved:
        mode = "HEAD-only pass" if head_only else "acquisition pass"
        print(
            f"{mode} left {len(unresolved)} of {len(uris)} objects unresolved; "
            f"checkpoint: {output}",
            file=sys.stderr,
        )
        return 1
    validate_checkpoint(checkpoint, uris, require_complete=True)
    print(f"Acquired {len(uris)} BOTS SHA-256 checksums in {output}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire SHA-256 checksums and S3 audit metadata for every unique "
            "BOTS manifest URI. Requests use requester-pays access."
        ),
        epilog=(
            "HEAD-provided SHA-256 values are trusted only when S3 labels them "
            "FULL_OBJECT. Other objects are streamed and hashed unless --head-only "
            "is set. ETags are retained for audit purposes and never used as hashes."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--head-only",
        action="store_true",
        help=(
            "issue HEAD requests and checkpoint metadata, but do not download "
            "objects without a usable FULL_OBJECT SHA-256; exit nonzero if unresolved"
        ),
    )
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="validate manifest URIs and any existing checkpoint without S3 calls",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="process at most N unresolved URIs in this run, in sorted order",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"checkpoint path (default: {OUTPUT_PATH})",
    )
    parser.add_argument(
        "--profile",
        help="optional AWS shared-config profile name (default: boto3 credential chain)",
    )
    args = parser.parse_args()
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be zero or greater")
    if args.validate_only and args.limit is not None:
        parser.error("--limit cannot be combined with --validate-only")
    return args


def main() -> int:
    args = parse_args()
    try:
        uris = manifest_uris()
        checkpoint = load_checkpoint(args.output, uris)
        resolved = len(checkpoint["files"])
        audited = len(checkpoint["objects"])
        if args.validate_only:
            validate_checkpoint(checkpoint, uris, require_complete=True)
            print(
                f"Validated {len(uris)} unique BOTS manifest URIs; "
                f"checkpoint has {resolved} resolved and {audited} audited objects"
            )
            return 0
        return acquire(
            uris,
            checkpoint,
            output=args.output,
            profile=args.profile,
            limit=args.limit,
            head_only=args.head_only,
        )
    except (AcquisitionError, OSError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
