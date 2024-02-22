from typing import List
from test_model import simple_setup_1
from tcsfw.address import AnyAddress, EndpointAddress, IPAddress, Protocol
from tcsfw.inspector import Inspector
from tcsfw.model import ModelListener, IoTSystem, Host, Connection
from tcsfw.registry import Registry
from tcsfw.traffic import Flow, IPFlow


class AModelListener(ModelListener):
    def __init__(self):
        self.events = []
        self.labels: List[str] = []

    def systemReset(self, system: IoTSystem):
        self.events.append(system)
        self.labels.append(f"reset")

    def hostChange(self, host: Host):
        self.events.append(host)
        self.labels.append(f"host {host}")

    def connectionChange(self, connection: Connection):
        self.events.append(connection)
        self.labels.append(f"conn {connection}")

    def newFlow(self, source: AnyAddress, target: AnyAddress, flow: Flow, connection: Connection):
        self.events.append(flow)
        self.labels.append(f"flow {flow}")

    def __repr__(self):
        return "\n".join([f"{s}" for s in self.labels])


def test_model_events():
    sb = simple_setup_1()
    lis = AModelListener()
    reg = Registry(Inspector(sb.system))
    reg.system.model_listeners.append(lis)

    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert lis.events[0].name == "Device 1"
    assert lis.events[1].name == "Device 2"
    assert lis.events[2] == cs1
    assert lis.events[3].get_source_address() == IPAddress.new("192.168.0.1")
    assert lis.events[3].get_target_address() == IPAddress.new("192.168.0.2")
    # assert lis.events[4].name == "Device 1"
    assert lis.events[4].name == "1.0.0.3"
    assert lis.events[5] == cs2
    assert lis.events[6].get_source_address() == IPAddress.new("192.168.0.1")
    assert lis.events[6].get_target_address() == IPAddress.new("1.0.0.3")
    assert len(lis.events) == 7

    # identical flows -> no change
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 7

    # flow source port changes -> new events
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1102) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1104) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 9

    lis.events.clear()
    reg.reset(enable_all=True)
    assert len(lis.events) == 1
    assert lis.events[0] == reg.system


def test_registry_events():
    sb = simple_setup_1()
    reg = Registry(Inspector(sb.system))

    lis0 = AModelListener()
    reg.system.model_listeners.append(lis0)
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis0.events) == 7

    lis = AModelListener()
    reg.system.model_listeners = [lis]  # replace
    reg.reset(enable_all=True).do_all_tasks()

    # FIXME: We do not get one address event the 2nd time, as addresses are not cleared on reset
    # - If this is a problem, registry could keep track of learned addresses and clear them on reset

    assert len(lis.events) == 7
    for i in [(0, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)]:
        assert lis0.labels[i[0]] == lis.labels[i[1]], f"missmatch at {i[0]}, {i[1]}"
