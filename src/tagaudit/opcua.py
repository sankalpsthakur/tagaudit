"""Bounded local OPC UA read collector. No Write or Call service is exposed.

Install the optional asyncua dependency separately. The companion audit runs
without it. Use a server-enforced read-only role; client code is not access control.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import math
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .audit import AuditError, CSV_FIELDS, audit_csv, validate_profile
except ImportError:  # standalone downloaded kit
    from audit import AuditError, CSV_FIELDS, audit_csv, validate_profile

CLIENT_URI = "urn:tagaudit:collector"
WIRE_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
WIRE_LIMIT = ((datetime(9999,12,31,23,59,59,tzinfo=timezone.utc)-WIRE_EPOCH).days*86400
              +86399)*10_000_000


def _wire_iso(ticks):
    """Preserve 100-ns DateTime ticks; platform boundary sentinels remain missing."""
    if ticks is None or not 0 < ticks < WIRE_LIMIT:
        return ""
    seconds,remainder=divmod(ticks,10_000_000)
    stamp=WIRE_EPOCH+timedelta(seconds=seconds)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S")+f".{remainder*100:09d}+00:00"


def _decode_read_response(data):
    """Decode one Read result in Part 6 field order without global library patches.

    asyncua 2.0.1's generic DataValue codec places ServerTimestamp before
    SourcePicoseconds. The transport/session/security machinery remains asyncua's.
    """
    from asyncua import ua
    from asyncua.ua import ua_binary as binary
    try:
        if binary.nodeid_from_binary(data)!=ua.NodeId(ua.ObjectIds.ReadResponse_Encoding_DefaultBinary):
            raise ua.UaError("unexpected Read response type")
        header=binary.struct_from_binary(ua.ResponseHeader,data)
        header.ServiceResult.check()
        if binary.Primitives.Int32.unpack(data)!=1:
            raise ua.UaError("unexpected read result count")
        mask=binary.Primitives.Byte.unpack(data)
        if mask & 0xc0:
            raise ua.UaError("reserved DataValue encoding bits")
        value=binary.variant_from_binary(data) if mask & 1 else ua.Variant(None)
        status=ua.StatusCode(binary.Primitives.UInt32.unpack(data)) if mask & 2 else ua.StatusCode(0)
        source=binary.Primitives.Int64.unpack(data) if mask & 4 else None
        source_pico=binary.Primitives.UInt16.unpack(data) if mask & 16 else None
        server=binary.Primitives.Int64.unpack(data) if mask & 8 else None
        server_pico=binary.Primitives.UInt16.unpack(data) if mask & 32 else None
        diagnostics=binary.Primitives.Int32.unpack(data)
        if diagnostics not in (0,1):
            raise ua.UaError("unexpected diagnostic count")
        for _ in range(diagnostics):
            binary.struct_from_binary(ua.DiagnosticInfo,data)
        if len(data):
            raise ua.UaError("trailing Read response bytes")
        return ua.DataValue(value,status),{
            "source_datetime_100ns_ticks":source,"server_datetime_100ns_ticks":server,
            "source_picoseconds_10ps_intervals":source_pico,
            "server_picoseconds_10ps_intervals":server_pico,
            "source_picoseconds_effective_10ps_intervals":min(source_pico,9999) if source is not None and source_pico is not None else None,
            "server_picoseconds_effective_10ps_intervals":min(server_pico,9999) if server is not None and server_pico is not None else None,
        }
    except ua.UaError:
        raise
    except (ValueError,TypeError,EOFError,OverflowError,IndexError) as exc:
        raise ua.UaError("malformed Read response") from exc


async def _read_value(node):
    from asyncua import ua
    request=ua.ReadRequest()
    request.Parameters=ua.ReadParameters(TimestampsToReturn=ua.TimestampsToReturn.Both,
        NodesToRead=[ua.ReadValueId(NodeId=node.nodeid,AttributeId=ua.AttributeIds.Value)])
    # This pinned, session-scoped adapter does not alter the installed dependency.
    return _decode_read_response(await node.session._send_request(request))


def validate_connection(endpoint, samples, interval, security, insecure_local_test):
    try:
        url = urlsplit(endpoint)
        port = url.port
    except (TypeError, ValueError) as exc:
        raise AuditError("invalid OPC UA endpoint") from exc
    if (url.scheme != "opc.tcp" or not url.hostname or not port or url.username is not None
            or url.password is not None or url.query or url.fragment):
        raise AuditError("use an explicit opc.tcp endpoint with a port and no embedded credentials")
    if isinstance(samples, bool) or not isinstance(samples, int) or not 1 <= samples <= 1000:
        raise AuditError("samples must be an integer from 1 to 1000")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not math.isfinite(interval):
        raise AuditError("interval must be finite")
    if not 0.05 <= interval <= 60 or (samples-1)*interval > 600:
        raise AuditError("interval must be 0.05 to 60 seconds, with at most 600 seconds between samples")
    try:
        loopback = ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        loopback = url.hostname.lower() == "localhost"
    if insecure_local_test:
        if not loopback or security:
            raise AuditError("plaintext test mode requires a loopback endpoint and no security options")
    elif not security or set(security) != {"certificate", "private_key", "server_certificate"}:
        raise AuditError("SignAndEncrypt requires client certificate, private key and pinned server certificate")
    return url


def _iso(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        return ""  # never substitute the receiver clock for a missing source/server timestamp
    return value.astimezone(timezone.utc).isoformat()


def _unit_text(value):
    if isinstance(value, str):
        text = value
    else:
        text = getattr(getattr(value, "DisplayName", None), "Text", None)
    return text.strip() if isinstance(text, str) and 0 < len(text.strip()) <= 256 else ""


def _value_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str) and len(value) <= 256:
        return value
    return ""


def _unit_metadata(value):
    """Retain declared unit identity separately from the normalized CSV label."""
    def text(item):
        return item if isinstance(item,str) and len(item)<=2048 else None
    if isinstance(value,str):
        return {"kind":"string_label_only","label":text(value)}
    return {"kind":"decoded_unit_structure","namespace_uri":text(getattr(value,"NamespaceUri",None)),
        "unit_id":getattr(value,"UnitId",None),
        "display_name":text(getattr(getattr(value,"DisplayName",None),"Text",None)),
        "description":text(getattr(getattr(value,"Description",None),"Text",None)),
        "text_limit":"Fields exceeding 2048 characters are unavailable, not truncated labels"}


async def collect(profile, endpoint, *, samples=5, interval=1.0, security=None,
                  insecure_local_test=False, credentials=None, application_uri=CLIENT_URI):
    """Read explicitly mapped nodes and their unit properties, then close the session.

    Sequence numbers identify collector sample groups, not PLC counters. The
    returned unit_origin records how the collector obtained the unit text.
    """
    profile = validate_profile(profile)
    validate_connection(endpoint, samples, interval, security, insecure_local_test)
    if profile["quality_encoding"] != "opcua_status_code":
        raise AuditError("the OPC UA collector requires raw opcua_status_code quality")
    if any(not tag.get("source_node") for tag in profile["tags"]):
        raise AuditError("every collected tag requires an explicit source_node")
    if not isinstance(application_uri, str) or not application_uri.startswith("urn:"):
        raise AuditError("client application URI must be an explicit urn")
    from asyncua import Client, ua
    from asyncua.crypto import security_policies, uacrypto
    from importlib.metadata import version

    if version("asyncua")!="2.0.1":
        raise AuditError("the bounded binary read adapter requires asyncua 2.0.1")

    client = Client(endpoint, timeout=5, auto_reconnect=False)
    client.application_uri = application_uri
    client.name = "tagaudit OPC UA collector"
    pin = None
    if security:
        cert = await uacrypto.load_certificate(str(security["server_certificate"]))
        now = datetime.now(timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise AuditError("pinned server certificate is outside its validity period")
        pin = hashlib.sha256(uacrypto.der_from_x509(cert)).hexdigest()
        await client.set_security(security_policies.SecurityPolicyBasic256Sha256,
            str(security["certificate"]), str(security["private_key"]),
            server_certificate=str(security["server_certificate"]),
            mode=ua.MessageSecurityMode.SignAndEncrypt)
    if credentials:
        if insecure_local_test:
            raise AuditError("credentials are not permitted in plaintext test mode")
        client.set_user(credentials[0])
        client.set_password(credentials[1])

    capture = str(uuid.uuid4())
    rows, issues, metadata = [], [], []

    async def capture_session():
        async with client:
            nodes = [(tag, client.get_node(tag["source_node"])) for tag in profile["tags"]]
            for sequence in range(samples):
                for tag, node in nodes:
                    row = dict.fromkeys(CSV_FIELDS, "")
                    row.update(capture_id=capture, asset_id=profile["asset_id"],
                               sequence=str(sequence), tag=tag["name"])
                    detail={"sequence":sequence,"tag":tag["name"],"source_picoseconds_10ps_intervals":None,
                        "server_picoseconds_10ps_intervals":None,"unit_metadata":None}
                    try:
                        value,wire=await _read_value(node)
                        row["received_timestamp"] = _iso(datetime.now(timezone.utc))
                        row["value"] = _value_text(value.Value.Value if value.Value is not None else None)
                        row["status_code"] = f"0x{value.StatusCode.value:08x}" if value.StatusCode is not None else ""
                        row["source_timestamp"] = _wire_iso(wire["source_datetime_100ns_ticks"])
                        row["server_timestamp"] = _wire_iso(wire["server_datetime_100ns_ticks"])
                        detail.update(wire)
                    except (ua.UaError, OSError, asyncio.TimeoutError) as exc:
                        row["received_timestamp"] = _iso(datetime.now(timezone.utc))
                        issues.append({"sequence": sequence, "tag": tag["name"],
                                       "stage": "value_read", "error_type": type(exc).__name__})
                    try:
                        units = (client.get_node(tag["units_node"]) if tag.get("units_node")
                                 else await node.get_child(["0:EngineeringUnits"]))
                        unit_value=await units.read_value()
                        row["unit"] = _unit_text(unit_value)
                        detail["unit_metadata"]=_unit_metadata(unit_value)
                        row["unit_origin"] = "server_property" if row["unit"] else "missing"
                    except (ua.UaError, OSError, asyncio.TimeoutError) as exc:
                        row["unit_origin"] = "missing"
                        issues.append({"sequence": sequence, "tag": tag["name"],
                                       "stage": "unit_read", "error_type": type(exc).__name__})
                    rows.append(row)
                    metadata.append(detail)
                if sequence+1 < samples:
                    await asyncio.sleep(interval)

    await asyncio.wait_for(capture_session(), timeout=630)
    return {"rows": rows, "issues": issues, "metadata":metadata,"connection": {
        "endpoint": endpoint, "security_mode": "None (explicit loopback test)" if insecure_local_test else "Basic256Sha256/SignAndEncrypt",
        "pinned_server_der_sha256": pin, "client_application_uri": application_uri,
        "asyncua_version": version("asyncua"), "samples": samples, "interval_seconds": interval,
        "sequence_basis": "collector-generated sample index; not a PLC sequence or source replay defense",
        "access_scope": "application issues node/metadata reads; server-side read-only role must be provisioned separately",
        "timestamp_request":"Both source and server timestamps explicitly requested",
        "timestamp_scope": "CSV retains wire DateTime at 100-ns resolution via a bounded binary Read adapter; receiver clock recorded after value read",
        "wire_datetime_low_ticks":"retained_in_csv_and_integer_metadata",
        "decoded_datetime_resolution_nanoseconds":100,
        "picosecond_scope":"Metadata retains raw 10-ps fields and effective values capped at 9999 when their DateTime is present; absent is null. Picoseconds are not added to CSV timestamps.",
        "wire_time_check_state":"CSV audit covers DateTime ticks; sub-100-ns picosecond offsets and physical clock accuracy remain outside audit scope",
        "read_codec":"tagaudit bounded single-result Part 6 adapter for asyncua 2.0.1; transport/security unchanged",
        "metadata_scope": "unit label reads are separate from DataValue reads, not an atomic server snapshot"}}


def csv_text(rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def main(argv=None, prog=None):
    parser = argparse.ArgumentParser(prog=prog, description="Collect a bounded local OPC UA read capture and audit it.")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--server-certificate", type=Path)
    parser.add_argument("--application-uri", default=CLIENT_URI)
    parser.add_argument("--username-env")
    parser.add_argument("--password-env")
    parser.add_argument("--insecure-local-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.profile.stat().st_size > 256_000:
            raise AuditError("profile exceeds the size limit")
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        supplied = {"certificate": args.certificate, "private_key": args.private_key,
                    "server_certificate": args.server_certificate}
        security = {key: value for key, value in supplied.items() if value is not None} or None
        credentials = None
        if args.username_env or args.password_env:
            if not args.username_env or not args.password_env:
                raise AuditError("supply both credential environment variable names")
            credentials = (os.environ.get(args.username_env), os.environ.get(args.password_env))
            if not all(credentials):
                raise AuditError("credential environment variables must be set")
        capture = asyncio.run(collect(profile, args.endpoint, samples=args.samples, interval=args.interval,
            security=security, insecure_local_test=args.insecure_local_test,
            credentials=credentials, application_uri=args.application_uri))
        content = csv_text(capture.pop("rows"))
        report = audit_csv(profile, content)
        report["input_file_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        report["collection"] = capture
        args.csv.write_text(content, encoding="utf-8", newline="")
        args.output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
        print(json.dumps(report["summary"]))
        return 0 if report["summary"]["checks_passed"] else 2
    except AuditError as exc:
        parser.exit(1, f"Collector failed: {exc}\n")
    except Exception as exc:
        # Avoid echoing server error payloads, credentials or certificate paths.
        parser.exit(1, f"Collector failed: {type(exc).__name__}\n")


if __name__ == "__main__":
    raise SystemExit(main())
