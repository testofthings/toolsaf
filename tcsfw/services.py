"""Services with dedicated logic"""

from typing import Any, Callable, Dict, List, Set, Optional

from tcsfw.address import EndpointAddress, Protocol, IPAddress
from tcsfw.basics import ConnectionType, HostType
from tcsfw.model import Service, NetworkNode, Connection, Host, Addressable
from tcsfw.traffic import IPFlow, Flow, Event, Evidence


class DHCPService(Service):
    """DHCP server service"""
    def __init__(self, parent: Addressable, name="DHCP"):
        super().__init__(name, parent)
        # match any traffic with UDP port 67
        self.addresses.add(EndpointAddress.any(Protocol.UDP, 67))
        self.description = "DHCP service"
        self.clients: Set[Host] = set()
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        # reply does not come from the broadcast address
        self.reply_from_other_address = True

    def new_connection(self, connection: Connection, flow: Flow, target: bool):
        assert isinstance(flow, IPFlow), "Bad DHCP flow"
        if target:
            return
        # response to client send by this DHCP service, learn IP
        if flow.source[2] == 67 and flow.target[2] == 68:
            client = connection.source.get_parent_host()
            self.get_system().learn_ip_address(client, flow.target[1])


class DNSService(Service):
    """DNS service"""
    def __init__(self, parent: Addressable, name="DNS"):
        super().__init__(name, parent)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.captive_portal = False
        self.get_system().message_listeners[self] = Protocol.DNS


class NameEvent(Event):
    """DNS name event"""
    def __init__(self, evidence: Evidence, service: Optional[DNSService], name: str,
                 address: Optional[IPAddress] = None, peers: List[NetworkNode] = None):
        super().__init__(evidence)
        self.service = service
        self.name = name
        self.address = address
        self.peers = [] if peers is None else peers  # The communicating peers

    def get_value_string(self) -> str:
        return f"{self.name}={self.address}" if self.address else self.name

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict:
        r = {
            "name": self.name,
        }
        if self.service:
            r["service"] = id_resolver(self.service)
        if self.address:
            r["address"] = self.address.get_parseable_value()
        if self.peers:
            r["peers"] = [id_resolver(p) for p in self.peers]
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict, entity_resolver: Callable[[Any], Any]):
        """Decode event from JSON"""
        name = data["name"]
        service = entity_resolver(data.get("service")) if "service" in data else None
        assert service is None or isinstance(service, DNSService), f"Bad service {service.__class__.__name__}"
        address = IPAddress.new(data.get("address")) if "address" in data else None
        peers = [entity_resolver(p) for p in data.get("peers", [])]
        assert all(p for p in peers)
        return NameEvent(evidence, service, name, address, peers)

    def __eq__(self, other):
        if not isinstance(other, NameEvent):
            return False
        return self.service == other.service and self.name == other.name and self.address == other.address

    def __hash__(self):
        return self.name.__hash__() ^ (self.address.__hash__() if self.address else 0)

    def __repr__(self):
        return f"{self.address}" + (f" '{self.name}'" if self.name else "")
