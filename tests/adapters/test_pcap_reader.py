import pathlib
from toolsaf.core.inspector import Inspector

from toolsaf.core.model import IoTSystem
from toolsaf.adapters.pcap_reader import PCAPReader
from toolsaf.core.registry import Registry
from toolsaf.common.traffic import IPFlow, EvidenceSource
from toolsaf.common.address import IPAddress
from tests.test_model import Setup


def test_pcap():
    m = Registry(Inspector(IoTSystem()))
    pcap = PCAPReader.inspect(pathlib.Path("tests/samples/pcap/deltaco-setup.pcap"), m)
    cs = m.logging.collect_flows()

    # FIXME: External connections are not filtered ou

    c = m.connection(IPFlow.tcp_flow(source_hw="7c:f6:66:24:a7:36", target_ip="18.195.249.137", target_port=443))
    c_flows = cs[c]
    assert len(c_flows) == 12

    c = m.connection(IPFlow.udp_flow(source_hw="86:df:86:76:53:bd", target_hw="dc:a6:32:28:34:e3", target_port=53))
    c_flows = cs[c]
    assert len(c_flows) == 2


def _connections(entity):
    connections = []
    for connection in entity.connections:
        connections.append((connection.source, connection.target.parent, connection.target.name))
    return connections


def test_process_file():
    setup = Setup()
    reader = PCAPReader(setup.get_system())

    device = setup.system.device("Device")
    app = setup.system.mobile("App")
    backend_1 = setup.system.backend("Backend1")
    backend_2 = setup.system.backend("Backend2")

    device.new_address_(IPAddress.new("10.42.0.184"))
    app.new_address_(IPAddress.new("10.42.0.133"))
    backend_1.new_address_(IPAddress.new("18.193.211.120"))
    backend_2.new_address_(IPAddress.new("18.194.10.142"))

    #app >> device / TCP(port=6668)
    #app >> backend_1 / TLS
    #app >> backend_2 / TLS(port=8883)

    source = EvidenceSource("pcap", "test")
    with pathlib.Path("tests/samples/pcap/test.pcap").open("rb") as f:
        reader.process_file(f, "", setup.get_inspector(), source)

        conn = _connections(device.entity)
        assert (app.entity, device.entity, "TCP:6668") in conn

        conn = _connections(app.entity)
        assert (app.entity, device.entity, "TCP:6668") in conn
        assert (app.entity, backend_1.entity, "TCP:443") in conn
        assert (app.entity, backend_2.entity, "TCP:8883") in conn

        conn = _connections(backend_1.entity)
        assert (app.entity, backend_1.entity, "TCP:443") in conn

        conn = _connections(backend_2.entity)
        assert (app.entity, backend_2.entity, "TCP:8883") in conn
