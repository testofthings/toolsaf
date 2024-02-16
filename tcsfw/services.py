from typing import List, Set, Optional

from tcsfw.address import IPAddresses, EndpointAddress, Protocol, HWAddress, IPAddress
from tcsfw.model import Service, NetworkNode, Connection, Host, ConnectionType, HostType, Addressable, ExternalActivity
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
        self.peers = [] if peers is None else peers

    def get_value_string(self) -> str:
        return f"{self.name}={self.address}" if self.address else self.name

    def __eq__(self, other):
        if not isinstance(other, NameEvent):
            return False
        return self.service == other.service and self.name == other.name and self.address == other.address

    def __hash__(self):
        return self.name.__hash__() ^ (self.address.__hash__() if self.address else 0)

    def __repr__(self):
        return f"{self.address}" + (f" '{self.name}'" if self.name else "")
