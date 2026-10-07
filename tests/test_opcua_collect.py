import asyncio
import socket
from datetime import datetime, timedelta, timezone

import pytest

asyncua = pytest.importorskip("asyncua", reason="install the optional opcua extra for wire tests")
from asyncua import Client, Server, ua
from asyncua.crypto import cert_gen
from asyncua.crypto.permission_rules import PermissionRuleset, USER_TYPES
from cryptography.x509.oid import ExtendedKeyUsageOID

from tagaudit.opcua import CLIENT_URI, collect, csv_text, validate_connection
from tagaudit.audit import AuditError, audit_csv


def profile_template():
    return {"schema": "tagaudit.profile.v1", "asset_id": "bench-pump",
        "freshness_basis": "server", "quality_encoding": "opcua_status_code",
        "max_age_seconds": 10, "max_future_seconds": 0.25, "max_snapshot_skew_seconds": 1,
        "tags": [{"name": "pressure", "unit": "bar", "minimum": 0, "maximum": 16},
                 {"name": "speed", "unit": "%", "minimum": 0, "maximum": 100}]}


class ReadOnlyRules(PermissionRuleset):
    def __init__(self):
        self.observed = []
        self.forbidden = {ua.NodeId(ua.ObjectIds.WriteRequest_Encoding_DefaultBinary),
                          ua.NodeId(ua.ObjectIds.CallRequest_Encoding_DefaultBinary)}
        self.allowed = {ua.NodeId(code) for code in USER_TYPES} - self.forbidden

    def check_validity(self, user, action_type, body):
        self.observed.append(action_type)
        return action_type in self.allowed


async def make_server(mode="good", secure=None):
    server = Server()
    await server.init()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    endpoint = f"opc.tcp://127.0.0.1:{port}/tagaudit-test/"
    server.set_endpoint(endpoint)
    rules = ReadOnlyRules()
    policies = [ua.SecurityPolicyType.NoSecurity]
    if secure:
        await server.set_application_uri("urn:tagaudit:test:server")
        await server.load_certificate(secure["certificate"])
        await server.load_private_key(secure["private_key"])
        policies = [ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt]
    server.set_security_policy(policies, permission_ruleset=rules)
    namespace = await server.register_namespace("urn:tagaudit:test:telemetry")
    asset = await server.nodes.objects.add_object(namespace, "Pump")
    profile = profile_template()
    nodes = []
    now = datetime.now(timezone.utc)
    for tag, value in zip(profile["tags"], (8.0, 60.0), strict=True):
        node = await asset.add_variable(namespace, tag["name"], value)
        units = ua.EUInformation()
        units.DisplayName = ua.LocalizedText("kPa" if mode == "wrong_unit" and tag["name"] == "pressure" else tag["unit"])
        await node.add_property(ua.NodeId(0, namespace), ua.QualifiedName("EngineeringUnits", 0), units)
        tag["source_node"] = node.nodeid.to_string()
        stamp = now - timedelta(seconds=60) if mode == "stale_server" else now
        code = 0x40000000 if mode == "uncertain" and tag["name"] == "pressure" else 0
        if mode == "semantics" and tag["name"] == "pressure":
            code = 0x4000
        dv = ua.DataValue(ua.Variant(value, ua.VariantType.Double), ua.StatusCode(code),
                          SourceTimestamp=now-timedelta(hours=1), ServerTimestamp=stamp)
        await server.write_attribute_value(node.nodeid, dv)
        nodes.append(node)
    return server, endpoint, profile, nodes, rules


def test_actual_loopback_capture_reads_units_and_timestamps_with_no_write_or_call():
    async def run():
        server, endpoint, profile, nodes, rules = await make_server()
        await nodes[0].set_writable()  # permission rule, rather than node flags, must deny writes
        async with server:
            async with Client(endpoint) as probe:
                with pytest.raises(ua.UaStatusCodeError) as denied_write:
                    await probe.get_node(profile["tags"][0]["source_node"]).write_value(9.0)
                assert denied_write.value.code == ua.StatusCodes.BadUserAccessDenied
                with pytest.raises(ua.UaStatusCodeError) as denied_call:
                    await probe.nodes.server.call_method(ua.NodeId(999999))
                assert denied_call.value.code == ua.StatusCodes.BadUserAccessDenied
            assert rules.forbidden.issubset(set(rules.observed))
            rules.observed.clear()
            capture = await collect(profile, endpoint, samples=2, interval=0.05, insecure_local_test=True)
            assert not rules.forbidden.intersection(rules.observed)
            assert (await nodes[0].read_value()) == 8.0
            return profile, capture
    profile, capture = asyncio.run(run())
    report = audit_csv(profile, csv_text(capture["rows"]))
    assert report["summary"]["checks_passed"], report
    assert report["summary"]["passed_snapshots"] == 2
    assert len(capture["rows"]) == 4
    assert capture["rows"][0]["unit_origin"] == "server_property"
    assert report["rows"][0]["source_age_seconds"] >= 3600
    assert capture["issues"] == []


@pytest.mark.parametrize("mode,reason", [("wrong_unit", "unit_mismatch"),
    ("stale_server", "stale_server_timestamp"), ("uncertain", "quality_uncertain"),
    ("semantics", "metadata_changed_requires_review")])
def test_wire_metadata_faults_remain_visible(mode, reason):
    async def run():
        server, endpoint, profile, _, _ = await make_server(mode)
        async with server:
            capture = await collect(profile, endpoint, samples=1, insecure_local_test=True)
            return audit_csv(profile, csv_text(capture["rows"]))
    report = asyncio.run(run())
    assert not report["summary"]["checks_passed"]
    assert reason in report["rows"][0]["reasons"], report


def test_missing_unit_property_is_not_replaced_by_the_expected_profile_unit():
    async def run():
        server, endpoint, profile, _, _ = await make_server()
        profile["tags"][0]["units_node"] = "ns=2;s=missing-unit-property"
        async with server:
            capture = await collect(profile, endpoint, samples=1, insecure_local_test=True)
            return profile, capture
    profile, capture = asyncio.run(run())
    assert capture["rows"][0]["unit"] == ""
    assert capture["rows"][0]["unit_origin"] == "missing"
    assert capture["issues"][0]["stage"] == "unit_read"
    assert not audit_csv(profile, csv_text(capture["rows"]))["summary"]["checks_passed"]


@pytest.mark.parametrize("endpoint,security,plaintext,samples,interval", [
    ("opc.tcp://192.0.2.10:4840/", None, True, 1, 1),
    ("opc.tcp://192.0.2.10:4840/", None, False, 1, 1),
    ("opc.tcp://user:password@127.0.0.1:4840/", None, True, 1, 1),
    ("http://127.0.0.1:4840/", None, True, 1, 1),
    ("opc.tcp://127.0.0.1/", None, True, 1, 1),
    ("opc.tcp://127.0.0.1:4840/", None, True, 0, 1),
    ("opc.tcp://127.0.0.1:4840/", None, True, 1000, 60),
    ("opc.tcp://127.0.0.1:4840/", None, True, 1, float("nan")),
    ("opc.tcp://127.0.0.1:4840/", {"server_certificate": "one.der"}, False, 1, 1),
])
def test_unsafe_or_unbounded_connections_reject_before_network(endpoint, security, plaintext, samples, interval):
    with pytest.raises(AuditError):
        validate_connection(endpoint, samples, interval, security, plaintext)


def test_encrypted_pinned_certificate_capture_and_mismatched_pin(tmp_path):
    async def run():
        hostname = socket.gethostname()
        server_key, server_cert = tmp_path/"server-key.pem", tmp_path/"server.der"
        client_key, client_cert = tmp_path/"client-key.pem", tmp_path/"client.der"
        await cert_gen.setup_self_signed_certificate(server_key, server_cert, "urn:tagaudit:test:server",
            hostname, [ExtendedKeyUsageOID.SERVER_AUTH], {"organizationName": "Forge synthetic test"})
        await cert_gen.setup_self_signed_certificate(client_key, client_cert, CLIENT_URI,
            hostname, [ExtendedKeyUsageOID.CLIENT_AUTH], {"organizationName": "Forge synthetic test"})
        server, endpoint, profile, _, rules = await make_server(secure={"certificate": server_cert, "private_key": server_key})
        config = {"certificate": client_cert, "private_key": client_key, "server_certificate": server_cert}
        async with server:
            capture = await collect(profile, endpoint, samples=1, security=config)
            assert not rules.forbidden.intersection(rules.observed)
            assert audit_csv(profile, csv_text(capture["rows"]))["summary"]["checks_passed"]
            # A distinct certificate with the SAME key exercises session pin equality,
            # rather than merely an inability to decrypt with the wrong public key.
            wrong_cert = tmp_path/"different-server.der"
            await cert_gen.setup_self_signed_certificate(server_key, wrong_cert, "urn:tagaudit:test:server",
                hostname, [ExtendedKeyUsageOID.SERVER_AUTH], {"organizationName": "Different synthetic pin"})
            with pytest.raises(ua.UaError, match="certificate mismatch"):
                await collect(profile, endpoint, samples=1, security={**config, "server_certificate": wrong_cert})
            return capture
    capture = asyncio.run(run())
    assert capture["connection"]["security_mode"] == "Basic256Sha256/SignAndEncrypt"
    assert len(capture["connection"]["pinned_server_der_sha256"]) == 64
