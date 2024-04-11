from tcsfw.address import Addresses, EndpointAddress, Protocol
from tcsfw.verdict import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_interface import PropertyAddressEvent, PropertyEvent
from tcsfw.main import DNS
from tcsfw.property import Properties, PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import Evidence, EvidenceSource, IPFlow


def test_property_event():
    sb = SystemBackend()
    dev0 = sb.device()
    evi = Evidence(EvidenceSource("Source A"))

    entities = {
        dev0.entity: 1,
    }
    ent_reverse = {v: k for k, v in entities.items()}

    p = PropertyEvent(evi, dev0.entity, PropertyKey("prop-a").verdict(Verdict.PASS))
    js = p.get_data_json(entities.get)
    assert js == {
        'entity': 1, 
        'key': 'prop-a', 
        'verdict': 'Pass'
    }

    p2 = PropertyEvent.decode_data_json(evi, js, ent_reverse.get)
    assert p2.get_verdict() == Verdict.PASS
    assert p == p2


def test_property_address_event():
    sb = SystemBackend()
    dev0 = sb.device()
    evi = Evidence(EvidenceSource("Source A"))

    p = PropertyAddressEvent(evi, Addresses.parse_address("1.2.3.4"), PropertyKey("prop-a").verdict(Verdict.FAIL))
    js = p.get_data_json(lambda x: None)
    assert js == {
        'address': "1.2.3.4",
        'key': 'prop-a',
        'verdict': 'Fail'
    }

    p2 = PropertyAddressEvent.decode_data_json(evi, js, lambda x: None)
    assert p2.get_verdict() == Verdict.FAIL
    assert p == p2

    p = PropertyAddressEvent(evi, EndpointAddress.hw("6:5:4:3:2:1", Protocol.UDP, 9090),
                             PropertyKey("prop-a").verdict(Verdict.FAIL))
    js = p.get_data_json(lambda x: None)
    assert js == {
        'address': "06:05:04:03:02:01|hw/udp:9090",
        'key': 'prop-a',
        'verdict': 'Fail'
    }

    p2 = PropertyAddressEvent.decode_data_json(evi, js, lambda x: None)
    assert p2.get_verdict() == Verdict.FAIL
    assert p == p2


def test_name_event():
    sb = SystemBackend()
    dev0 = sb.device()
    service = dev0 / DNS
    evi = Evidence(EvidenceSource("Source A"))

    entities = {
        dev0.entity: 1,
        service.entity: 12,
    }
    ent_reverse = {v: k for k, v in entities.items()}

    p = NameEvent(evi, service.entity, "www.example.com")
    js = p.get_data_json(entities.get)
    assert js == {
        'service': 12,
        'name': 'www.example.com'
    }

    p2 = NameEvent.decode_data_json(evi, js, ent_reverse.get)
    assert p2.service == service.entity
    assert p2.name == "www.example.com"
    assert p == p2


def test_ipflow_event():
    p = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234)
    Properties.MITM.put_verdict(p.properties, Verdict.PASS)

    js = p.get_data_json(lambda x: None)
    assert js == {
        'protocol': 'udp',
        'source_hw': '01:00:00:00:00:01',
        'source': '192.168.0.1',
        'source_port': 1100,
        'target_hw': '01:00:00:00:00:02',
        'target': '192.168.0.2',
        'target_port': 1234,
        'properties': {
            'check:mitm': {'verdict': 'Pass'}
        }
    }

    evi = Evidence(EvidenceSource("Source A"))
    p2 = IPFlow.decode_data_json(evi, js, lambda x: None)
    assert p == p2
