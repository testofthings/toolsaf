from test_model import simple_setup_1
from tcsfw.address import EndpointAddress, Protocol
from tcsfw.inspector import Inspector
from tcsfw.model import ModelListener, IoTSystem, Host, Connection
from tcsfw.registry import Registry
from tcsfw.traffic import IPFlow
from tcsfw.verdict import FlowEvent


class AModelListener(ModelListener):
    def __init__(self):
        self.events = []

    def systemReset(self, system: IoTSystem):
        self.events.append(system)

    def hostChange(self, host: Host):
        self.events.append(host)

    def connectionChange(self, connection: Connection):
        self.events.append(connection)

    def newFlow(self, flow: FlowEvent, connection: Connection):
        self.events.append(flow)

    def __repr__(self):
        return "\n".join([f"{e}" for e in self.events])


def test_model_events():
    sb = simple_setup_1()
    lis = AModelListener()
    reg = Registry(Inspector(sb.system))
    reg.system.model_listeners.append(lis)

    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 8
    assert lis.events[0].name == "Device 1"
    assert lis.events[1].name == "Device 2"
    assert lis.events[2] == cs1
    assert lis.events[3].endpoints == (EndpointAddress.hw("1:0:0:0:0:1", Protocol.UDP, 1100),
                                       EndpointAddress.ip("192.168.0.2", Protocol.UDP, 1234))
    assert lis.events[4].name == "Device 1"
    assert lis.events[5].name == "1.0.0.3"
    assert lis.events[6] == cs2
    assert lis.events[7].endpoints == (EndpointAddress.hw("1:0:0:0:0:1", Protocol.UDP, 1100),
                                       EndpointAddress.ip("1.0.0.3", Protocol.UDP, 1234))

    # identical flows -> no change
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 8

    # flow source port changes -> new events
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1102) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1104) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 12

    lis.events.clear()
    reg.reset()
    assert len(lis.events) == 1
    assert lis.events[0] == reg.system


def test_registry_events():
    sb = simple_setup_1()
    lis = AModelListener()
    reg = Registry(Inspector(sb.system))

    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))

    reg.system.model_listeners.append(lis)
    reg.reset().do_all_tasks()

    assert len(lis.events) == 8
