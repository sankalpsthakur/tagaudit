"""Spec-ordered byte fixtures, independent of asyncua's DataValue serializer."""
import struct
from datetime import datetime,timezone

import pytest

pytest.importorskip("asyncua", reason="install the optional opcua extra for wire tests")
from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.ua import ua_binary as binary

from tagaudit.opcua import _decode_read_response,_wire_iso,WIRE_LIMIT

SOURCE=ua.datetime_to_win_epoch(datetime(2026,10,1,8,tzinfo=timezone.utc))+1234
SERVER=SOURCE+10_000_000


def frame(mask,source_pico=5678,server_pico=8765):
    body=bytes([mask])
    if mask & 1:body+=struct.pack('<Bd',11,8.)
    if mask & 2:body+=struct.pack('<I',0x40000000)
    if mask & 4:body+=struct.pack('<q',SOURCE)
    if mask & 16:body+=struct.pack('<H',source_pico)
    if mask & 8:body+=struct.pack('<q',SERVER)
    if mask & 32:body+=struct.pack('<H',server_pico)
    return (binary.nodeid_to_binary(ua.NodeId(ua.ObjectIds.ReadResponse_Encoding_DefaultBinary))
        +binary.struct_to_binary(ua.ResponseHeader())+struct.pack('<i',1)+body+struct.pack('<i',0))


@pytest.mark.parametrize('mask',range(64))
def test_all_optional_field_masks_follow_spec_order_and_keep_raw_ticks(mask):
    value,meta=_decode_read_response(Buffer(frame(mask)))
    assert value.Value.Value==(8. if mask & 1 else None)
    assert value.StatusCode.value==(0x40000000 if mask & 2 else 0)
    assert meta['source_datetime_100ns_ticks']==(SOURCE if mask & 4 else None)
    assert meta['server_datetime_100ns_ticks']==(SERVER if mask & 8 else None)
    assert meta['source_picoseconds_10ps_intervals']==(5678 if mask & 16 else None)
    assert meta['server_picoseconds_10ps_intervals']==(8765 if mask & 32 else None)
    assert meta['source_picoseconds_effective_10ps_intervals']==(5678 if mask & 20==20 else None)
    assert meta['server_picoseconds_effective_10ps_intervals']==(8765 if mask & 40==40 else None)


@pytest.mark.parametrize('raw',[9999,10000,65535])
def test_picosecond_wire_value_is_retained_and_effective_value_is_capped(raw):
    _,meta=_decode_read_response(Buffer(frame(63,raw,raw)))
    assert meta['source_picoseconds_10ps_intervals']==raw
    assert meta['source_picoseconds_effective_10ps_intervals']==min(raw,9999)


def test_wire_datetime_low_ticks_survive_csv_formatting():
    assert _wire_iso(SOURCE)=='2026-10-01T08:00:00.000123400+00:00'
    assert _wire_iso(SOURCE+1)=='2026-10-01T08:00:00.000123500+00:00'
    assert _wire_iso(None)==_wire_iso(0)==_wire_iso(-1)==_wire_iso(WIRE_LIMIT)==''
    assert _wire_iso(WIRE_LIMIT-1)=='9999-12-31T23:59:58.999999900+00:00'


@pytest.mark.parametrize('content',[frame(63)[:-1],frame(63)+b'x',frame(0xc0)])
def test_malformed_or_reserved_binary_values_are_rejected(content):
    with pytest.raises(ua.UaError):_decode_read_response(Buffer(content))


def test_same_stack_roundtrip_does_not_establish_wire_field_order():
    # The pinned upstream decoder interprets the independently ordered vector incorrectly.
    decoded=binary.struct_from_binary(ua.ReadResponse,Buffer(frame(63))).Results[0]
    assert decoded.ServerTimestamp!=datetime(2026,10,1,8,0,1,123,tzinfo=timezone.utc)
    assert decoded.SourcePicoseconds!=5678
