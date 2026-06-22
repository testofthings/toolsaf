from typing import Any, List, Tuple
from toolsaf.common.entity import Entity
from toolsaf.common.property import PropertyKey
from test_model import simple_setup_1
from toolsaf.core.inspector import Inspector
from toolsaf.core.event_logger import EventLogger
from toolsaf.core.model import ModelListener, Host, Connection, Service
from toolsaf.common.traffic import IPFlow


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
    event_logger = EventLogger(Inspector(sb.system))
    event_logger.get_system().model_listeners.append(lis)

    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:2", "192.168.0.2", 1234))
    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:3", "1.0.0.3", 1234))
    assert lis.labels == [
        'Device 1 => Device 2 UDP:1234 property check:expected=[Pass]',
        'Device 1 property check:expected=[Pass]',
        'conn Unexpected/Fail Device 1 => 1.0.0.3',
        'host Unexpected/Fail 1.0.0.3',
    ]

    # identical flows -> no change
    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:2", "192.168.0.2", 1234))
    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 4

    # flow source port changes -> no change
    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1102) >> ("a:0:0:0:0:2", "192.168.0.2", 1234))
    event_logger.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1104) >> ("a:0:0:0:0:3", "1.0.0.3", 1234))
    assert len(lis.events) == 4


def test_registry_events():
    sb = simple_setup_1()
    reg = EventLogger(Inspector(sb.system))

    lis0 = AModelListener()
    reg.get_system().model_listeners.append(lis0)
    reg.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:2", "192.168.0.2", 1234))
    reg.connection(IPFlow.UDP("a:0:0:0:0:1", "192.168.0.1", 1100) >> ("a:0:0:0:0:3", "1.0.0.3", 1234))
    assert lis0.labels == [
        'Device 1 => Device 2 UDP:1234 property check:expected=[Pass]',
        'Device 1 property check:expected=[Pass]',
        'conn Unexpected/Fail Device 1 => 1.0.0.3',
        'host Unexpected/Fail 1.0.0.3',
    ]
