from typing import Any, List, Tuple
from tcsfw.entity import Entity
from tcsfw.property import PropertyKey
from test_model import simple_setup_1
from tcsfw.address import AnyAddress, EndpointAddress, IPAddress, Protocol
from tcsfw.inspector import Inspector
from tcsfw.model import ModelListener, IoTSystem, Host, Connection, Service
from tcsfw.registry import Registry
from tcsfw.traffic import Flow, IPFlow


class AModelListener(ModelListener):
    def __init__(self):
        self.events = []
        self.labels: List[str] = []

    def connection_change(self, connection: Connection):
        self.events.append(connection)
        self.labels.append(f"conn {connection}")

    def host_change(self, host: Host):
        self.events.append(host)
        self.labels.append(f"host {host}")

    def address_change(self, host: Host):
        self.events.append(host)
        self.labels.append(f"address {host}")

    def service_change(self, service: Service):
        self.events.append(service)
        self.labels.append(f"service {service}")

    def property_change(self, entity: Entity, value: Tuple[PropertyKey, Any]):
        """Property changed. Not all changes create events, just the 'important' ones"""
        self.events.append(value)
        self.labels.append(f"{entity.long_name()} property {value[0]}={value[1]}")


    def __repr__(self):
        return "\n".join([f"{s}" for s in self.labels])


def test_model_events():
    sb = simple_setup_1()
    lis = AModelListener()
    reg = Registry(Inspector(sb.system))
    reg.system.model_listeners.append(lis)

    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert lis.labels == [
        'Device 1 => Device 2 UDP:1234 property check:expected=[Pass]',
        'Device 1 property check:expected=[Pass]',
        'conn Unexpected/Fail Device 1 => 1.0.0.3',
        'host Unexpected/Fail 1.0.0.3',
    ]

    # identical flows -> no change
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 4

    # flow source port changes -> no change
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1102) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1104) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 4

    lis.events.clear()
    reg.reset(enable_all=True)
    assert len(lis.events) == 0


def test_registry_events():
    sb = simple_setup_1()
    reg = Registry(Inspector(sb.system))

    lis0 = AModelListener()
    reg.system.model_listeners.append(lis0)
    cs1 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = reg.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert lis0.labels == [
        'Device 1 => Device 2 UDP:1234 property check:expected=[Pass]',
        'Device 1 property check:expected=[Pass]',
        'conn Unexpected/Fail Device 1 => 1.0.0.3',
        'host Unexpected/Fail 1.0.0.3',
    ]

    lis = AModelListener()
    reg.system.model_listeners = [lis]  # replace
    reg.reset(enable_all=True).apply_all_events()

    # FIXME: We do not get one address event the 2nd time, as addresses are not cleared on reset
    # - If this is a problem, registry could keep track of learned addresses and clear them on reset

    assert lis0.labels == lis.labels
