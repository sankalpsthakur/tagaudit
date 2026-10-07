import asyncio
from datetime import datetime,timezone
import struct

import pytest

pytest.importorskip("asyncua", reason="install the optional opcua extra for wire tests")
from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.ua import ua_binary
from tagaudit.opcua import collect


def test_collector_requests_both_timestamps_and_retains_wire_precision_metadata(monkeypatch):
    """A standards-conforming responder omits timestamps not requested."""
    requests=[]
    stamp=datetime(2026,10,1,8,tzinfo=timezone.utc)
    units=ua.EUInformation(NamespaceUri='urn:invented:units',UnitId=1234,
        DisplayName=ua.LocalizedText('bar'),Description=ua.LocalizedText('Invented declared unit'))
    class Session:
        async def _send_request(self,request):
            params=request.Parameters
            requests.append(params)
            ticks=ua.datetime_to_win_epoch(stamp)
            both=params.TimestampsToReturn==ua.TimestampsToReturn.Both
            response=(ua_binary.nodeid_to_binary(ua.NodeId(ua.ObjectIds.ReadResponse_Encoding_DefaultBinary))
                +ua_binary.struct_to_binary(ua.ResponseHeader())+struct.pack('<i',1)
                +struct.pack('<BBd',0x3d if both else 0x15,11,8.)
                +struct.pack('<qH',ticks,5678)+(struct.pack('<qH',ticks,0) if both else b'')
                +struct.pack('<i',0))
            return Buffer(response)
    class Node:
        nodeid=ua.NodeId('pressure',2)
        session=Session()
        async def get_child(self,_path):return self
        async def read_value(self):return units
    class Client:
        def __init__(self,*args,**kwargs):pass
        def get_node(self,_node):return Node()
        async def __aenter__(self):return self
        async def __aexit__(self,*_args):pass
    monkeypatch.setattr('asyncua.Client',Client)
    profile={'schema':'tagaudit.profile.v1','asset_id':'invented',
        'freshness_basis':'server','quality_encoding':'opcua_status_code','max_age_seconds':10,
        'max_future_seconds':.25,'max_snapshot_skew_seconds':1,
        'tags':[{'name':'pressure','unit':'bar','minimum':0,'maximum':16,'source_node':'ns=2;s=pressure'}]}
    capture=asyncio.run(collect(profile,'opc.tcp://127.0.0.1:4840/',samples=1,insecure_local_test=True))
    assert requests[0].TimestampsToReturn==ua.TimestampsToReturn.Both
    assert capture['rows'][0]['server_timestamp']=='2026-10-01T08:00:00.000000000+00:00'
    detail=capture['metadata'][0]
    assert detail['source_picoseconds_10ps_intervals']==5678
    assert detail['server_picoseconds_10ps_intervals']==0
    assert detail['unit_metadata']['unit_id']==1234
    assert detail['unit_metadata']['namespace_uri']=='urn:invented:units'
    assert capture['connection']['wire_datetime_low_ticks']=='retained_in_csv_and_integer_metadata'
