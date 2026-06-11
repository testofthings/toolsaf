"""Services with dedicated logic"""

from typing import List, Set, Optional
from datetime import datetime

from toolsaf.common.address import AnyAddress, DNSName, EndpointAddress, EntityTag, Protocol
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
            if self in client.children:
                # this service is source of connection - perhaps we missed original request
                client = connection.target.get_parent_host()
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
                 peers: Optional[List[Addressable]] = None, timestamp: Optional[datetime]=None):
        super().__init__(evidence)
        assert name or tag, "Name or tag must be set"
        self.service = service
        self.name = name
        self.tag = tag
        self.address = address
        self.peers = [] if peers is None else peers  # The communicating peers
        self.timestamp = timestamp

    def get_value_string(self) -> str:
        return f"{self.name or self.tag}={self.address}" if self.address else str(self.name or self.tag)

    def __eq__(self, other: object ) -> bool:
        if not isinstance(other, NameEvent):
            return False
        return self.service == other.service and self.name == other.name and self.address == other.address

    def __hash__(self) -> int:
        return hash(self.name) ^ hash(self.tag) ^ hash(self.address)
