"""Services with dedicated logic"""

from typing import Any, Callable, Dict, List, Set, Optional, Union

from toolsaf.common.address import AnyAddress, DNSName, EndpointAddress, EntityTag, Protocol, IPAddress
from toolsaf.common.basics import ConnectionType, HostType
from toolsaf.core.model import Service, Connection, Host, Addressable
from toolsaf.common.traffic import IPFlow, Flow, Event, Evidence


class DHCPService(Service):
    """DHCP server service"""
    def __init__(self, parent: Addressable, name: str="DHCP") -> None:
        super().__init__(name, parent)
        # match any traffic with UDP port 67
        self.addresses.add(EndpointAddress.any(Protocol.UDP, 67))
        self.description = "DHCP service"
        self.clients: Set[Host] = set()
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        # reply does not come from the broadcast address
        self.reply_from_other_address = True

    def new_connection(self, connection: Connection, flow: Flow, target: bool) -> None:
        assert isinstance(flow, IPFlow), "Bad DHCP flow"
        if target:
            return
        # response to client send by this DHCP service, learn IP
        if flow.source[2] == 67 and flow.target[2] == 68:
            client = connection.source.get_parent_host()
            self.get_system().learn_ip_address(client, flow.target[1])


class DNSService(Service):
    """DNS service"""
    def __init__(self, parent: Addressable, name: str="DNS") -> None:
        super().__init__(name, parent)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.captive_portal = False
        self.get_system().message_listeners[self] = Protocol.DNS


class NameEvent(Event):
    """Name or tag and address event"""
    def __init__(self, evidence: Evidence, service: Optional[DNSService], name: Optional[DNSName] = None,
                 tag: Optional[EntityTag] = None, address: Optional[AnyAddress] = None,
                 peers: Optional[List[Addressable]] = None):
        super().__init__(evidence)
        assert name or tag, "Name or tag must be set"
        self.service = service
        self.name = name
        self.tag = tag
        self.address = address
        self.peers = [] if peers is None else peers  # The communicating peers

    def get_value_string(self) -> str:
        return f"{self.name or self.tag}={self.address}" if self.address else str(self.name or self.tag)

    def get_data_json(self, id_resolver: Callable[[Any], Any]) -> Dict[str, Any]:
        r: Dict[str, Union[str, List[Any]]] = {}
        if self.name:
            r["name"] = self.name.name
        if self.tag:
            r["tag"] = self.tag.tag
        if self.service:
            r["service"] = id_resolver(self.service)
        if self.address:
            r["address"] = self.address.get_parseable_value()
        if self.peers:
            r["peers"] = [id_resolver(p) for p in self.peers]
        return r

    @classmethod
    def decode_data_json(cls, evidence: Evidence, data: Dict[str, Any],
                         entity_resolver: Callable[[Any], Any]) -> 'NameEvent':
        """Decode event from JSON"""
        name = DNSName(data["name"]) if "name" in data else None
        tag = EntityTag(data["tag"]) if "tag" in data else None
        service = entity_resolver(data["service"]) if "service" in data else None
        assert service is None or isinstance(service, DNSService), f"Bad service {service.__class__.__name__}"
        address = IPAddress.new(data["address"]) if "address" in data else None
        peers = [entity_resolver(p) for p in data.get("peers", [])]
        assert all(p for p in peers)
        return NameEvent(evidence, service, name, tag, address, peers)

    def __eq__(self, other: object ) -> bool:
        if not isinstance(other, NameEvent):
            return False
        return self.service == other.service and self.name == other.name and self.address == other.address

    def __hash__(self) -> int:
        return hash(self.name) ^ hash(self.tag) ^ hash(self.address)

    def __repr__(self) -> str:
        return self.get_value_string()
