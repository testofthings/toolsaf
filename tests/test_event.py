from toolsaf.common.address import Addresses, DNSName, EndpointAddress, Protocol
from toolsaf.common.verdict import Verdict
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.core.event_logger import LoggingEvent
from toolsaf.main import DNS, TLS
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import Evidence, EvidenceSource, IPFlow


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

    p = NameEvent(evi, service.entity, name=DNSName("www.example.com"))
    js = p.get_data_json(entities.get)
    assert js == {
        'service': 12,
        'name': 'www.example.com'
    }

    p2 = NameEvent.decode_data_json(evi, js, ent_reverse.get)
    assert p2.service == service.entity
    assert p2.name == DNSName("www.example.com")
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


def test_ipflow_log_event_verdict():
    sb = SystemBackend()
    conn = sb.device() >> sb.device() / TLS

    p = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234)

    log_ev = LoggingEvent(p)
    log_ev.pick_entity_verdict(conn.connection)
    assert log_ev.resolve_verdict() == Verdict.INCON

    log_ev.property_value = PropertyKey("non-verdict"), Verdict.FAIL
    assert log_ev.resolve_verdict() == Verdict.INCON
    log_ev.property_value = Properties.MITM.verdict(Verdict.INCON)
    assert log_ev.resolve_verdict() == Verdict.INCON
    log_ev.property_value = Properties.MITM.verdict(Verdict.PASS)
    assert log_ev.resolve_verdict() == Verdict.PASS
    log_ev.property_value = Properties.MITM.verdict(Verdict.FAIL)
    assert log_ev.resolve_verdict() == Verdict.FAIL

    conn.connection.set_seen_now()  # to set default EXPECTED property
    log_ev = LoggingEvent(p)
    log_ev.pick_entity_verdict(conn.connection)
    assert log_ev.resolve_verdict() == Verdict.PASS

    log_ev.property_value = Properties.MITM.verdict(Verdict.FAIL)
    assert log_ev.resolve_verdict() == Verdict.FAIL

    Properties.MITM.put_verdict(p.properties, Verdict.FAIL)
    log_ev = LoggingEvent(p)
    log_ev.pick_entity_verdict(conn.connection)
    assert log_ev.resolve_verdict() == Verdict.FAIL

    log_ev.property_value = Properties.MITM.verdict(Verdict.PASS)
    assert log_ev.resolve_verdict() == Verdict.FAIL
