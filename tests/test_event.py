from toolsaf.common.address import Addresses, DNSName, EndpointAddress, Protocol, HWAddress, IPAddress
from toolsaf.common.verdict import Verdict
from toolsaf.builder_backend import SystemBackend
from toolsaf.core.event_interface import PropertyAddressEvent, PropertyEvent
from toolsaf.core.event_logger import LoggingEvent
from toolsaf.main import DNS, TLS
from toolsaf.common.property import Properties, PropertyKey, PropertyVerdictValue
from toolsaf.core.services import NameEvent
from toolsaf.common.traffic import Evidence, EvidenceSource, IPFlow


def test_property_event():
    sb = SystemBackend()
    dev0 = sb.device()
    evi = Evidence(EvidenceSource("Source A"))

    p = PropertyEvent(evi, dev0.entity, PropertyKey("prop-a").verdict(Verdict.PASS))
    assert p.evidence == evi
    assert p.entity == dev0.entity
    assert p.key_value == (PropertyKey("prop-a"), PropertyVerdictValue(Verdict.PASS))
    assert p.get_verdict() == Verdict.PASS


def test_property_address_event():
    evi = Evidence(EvidenceSource("Source A"))

    p = PropertyAddressEvent(evi, Addresses.parse_address("1.2.3.4"), PropertyKey("prop-a").verdict(Verdict.FAIL))
    assert p.address == Addresses.parse_address("1.2.3.4")
    assert p.key_value == (PropertyKey("prop-a"), PropertyVerdictValue(Verdict.FAIL))
    assert p.get_verdict() == Verdict.FAIL

    p = PropertyAddressEvent(evi, EndpointAddress.hw("6:5:4:3:2:1", Protocol.UDP, 9090),
                             PropertyKey("prop-a").verdict(Verdict.FAIL))
    assert p.address == EndpointAddress.hw("6:5:4:3:2:1", Protocol.UDP, 9090)
    assert p.key_value == (PropertyKey("prop-a"), PropertyVerdictValue(Verdict.FAIL))
    assert p.get_verdict() == Verdict.FAIL


def test_name_event():
    sb = SystemBackend()
    dev0 = sb.device()
    service = dev0 / DNS
    evi = Evidence(EvidenceSource("Source A"))

    p = NameEvent(evi, service.entity, name=DNSName("www.example.com"))
    assert p.service == service.entity
    assert p.name == DNSName("www.example.com")
    assert p.tag is None
    assert p.address is None
    assert p.peers == []
    assert p.timestamp is None


def test_ipflow_event():
    p = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234)
    Properties.MITM.put_verdict(p.properties, Verdict.PASS)

    assert p.protocol == Protocol.UDP
    assert p.network is None
    assert p.reply is False
    assert p.timestamp is None
    assert p.properties == {Properties.MITM: PropertyVerdictValue(Verdict.PASS)}
    assert p.source == (HWAddress.new("1:0:0:0:0:1"), IPAddress.new("192.168.0.1"), 1100)
    assert p.target == (HWAddress.new("1:0:0:0:0:2"), IPAddress.new("192.168.0.2"), 1234)


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
