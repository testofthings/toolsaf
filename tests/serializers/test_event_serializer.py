from toolsaf.common.address import EndpointAddress, IPAddress, Protocol
from toolsaf.common.serializer.serializer import SerializerStream
from toolsaf.common.traffic import Evidence, EvidenceSource, HostScan, ServiceScan
from toolsaf.core.serializer.event_serializers import EventSerializer


def test_event_serializers():
    source = EvidenceSource(name="Tsource")
    s_events = [
        ServiceScan(Evidence(source, tail_ref="#ref"), EndpointAddress.ip("192.168.1.7", Protocol.TCP, 8000)),
        HostScan(Evidence(source), IPAddress.new("10.10.10.5"), endpoints=(
            EndpointAddress.ip("192.168.1.7", Protocol.TCP, 8000),
            EndpointAddress.ip("192.168.1.7", Protocol.TCP, 8002),
        )),
    ]
    ser = EventSerializer()
    stream = SerializerStream(ser)
    js = []
    for e in s_events:
        js.extend(ser.write_event(e, stream))
    assert [j['type'] for j in js] == ["source", "service-scan", "host-scan"]
    assert js[0]['name'] == "Tsource"
    assert js[1]['service_name'] == ""
    assert js[2]['host'] == "10.10.10.5"
