"""Shell command 'ps'"""

from io import BytesIO, TextIOWrapper
import re
from typing import Any, Dict, List, Set, Tuple
from tcsfw.address import AddressEnvelope, Addresses, AnyAddress, EndpointAddress, HWAddresses, IPAddress
from tcsfw.components import OperatingSystem
from tcsfw.event_interface import EventInterface, PropertyEvent
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey
from tcsfw.services import NameEvent
from tcsfw.tools import EndpointTool
from tcsfw.traffic import Evidence, EvidenceSource, IPFlow, Protocol, ServiceScan
from tcsfw.verdict import Verdict


class ShellCommandPs(EndpointTool):
    """Shell command 'ps' tool adapter"""
    def __init__(self, system: IoTSystem):
        super().__init__("shell-ps", ".txt", system)

    def process_endpoint(self, endpoint: AnyAddress, stream: BytesIO, interface: EventInterface,
                         source: EvidenceSource):
        node = self.system.get_endpoint(endpoint)

        columns: Dict[str, int] = {}
        os = OperatingSystem.get_os(node, add=self.load_baseline)

        # expected processes as regexps
        regexp_map = {}
        for user, ps_list in os.process_map.items():
            regexp_map[user] = [re.compile(ps) for ps in ps_list]

        properties: Dict[str, List[Tuple[PropertyKey, Any]]] = {}
        unseen: Dict[str, Set[str]] = {u: set(ps) for u, ps in os.process_map.items()}
        with TextIOWrapper(stream) as f:
            while True:
                line = f.readline().split(maxsplit=len(columns) -1 if columns else -1)
                if not line:
                    break
                if not columns:
                    # header line, use first two characters (headers are truncated for narrow data)
                    columns = {name[:2]: idx for idx, name in enumerate(line)}
                    continue
                if len(line) < len(columns):
                    continue  # bad line
                user = line[columns["US"]].strip()
                cmd = line[columns["CM"]].strip()
                pid = line[columns["PI"]].strip()  # using pid as unique identifier
                if cmd.startswith("[") and cmd.endswith("]"):
                    continue  # kernel thread
                cmd_0 = cmd.split()[0]
                if cmd_0 == "ps":
                    continue  # ps command itself
                if self.load_baseline:
                    # learning the processes
                    base_ps = os.process_map.setdefault(user, [])
                    if cmd_0 not in base_ps:
                        base_ps.append(f"^{cmd_0}")
                    continue
                exp_ps = regexp_map.get(user) if os else None
                if exp_ps is None:
                    self.logger.debug("User %s not in process map", user)
                    continue
                key = PropertyKey("process", user, str(pid))
                exp = f"{user} process: {cmd}"
                user_ps = properties.setdefault(user, [])
                for ps in exp_ps:
                    if ps.match(cmd):
                        user_ps.append(key.verdict(Verdict.PASS, explanation=exp))
                        unseen[user].discard(ps.pattern)
                        break
                else:
                    self.logger.debug("Command %s not expected process for %s", cmd, user)
                    user_ps.append(key.verdict(Verdict.FAIL, explanation=exp))
                    continue
                self.logger.debug("Command %s expected process for %s", cmd, user)

        if self.send_events:
            # send pass or fail properties per process and set-value per user
            evidence = Evidence(source)
            for user, ps in sorted(properties.items()):
                # seen processes, expected or not
                for prop in ps:
                    ev = PropertyEvent(evidence, os, prop)
                    interface.property_update(ev)
                set_p = PropertyKey("process", user).value_set(set(p[0] for p in ps))
                ev = PropertyEvent(evidence, os, set_p)
                interface.property_update(ev)
                # unseen processes
                unseen_ps = unseen.get(user, set())
                for n, ps_name in enumerate(sorted(unseen_ps)):
                    key = PropertyKey("process", user, f"-{n}")
                    ev = PropertyEvent(
                        evidence, os, key.verdict(Verdict.INCON, explanation=f"{user} process {ps_name} not seen"))
                    interface.property_update(ev)


class ShellCommandSs(EndpointTool):
    """Shell command 'ss' tool adapter"""
    def __init__(self, system: IoTSystem):
        super().__init__("shell-ss", ".txt", system)

    def _parse_address(self, addr: str) -> Tuple[str, str, int]:
        """Parse address into IP, interface, port"""
        ad_inf, _, port = addr.rpartition(":")
        ad, _, inf = ad_inf.partition("%")
        return ad if ad not in {"", "*", "0.0.0.0", "[::]"} else "", inf, int(port) if port not in {"", "*"} else -1

    LOCAL_ADDRESS = "Local_Address"
    PEER_ADDRESS = "Peer_Address"

    def process_endpoint(self, endpoint: AnyAddress, stream: BytesIO, interface: EventInterface,
                         source: EvidenceSource):
        columns: Dict[str, int] = {}
        local_ads = set()
        services: Set[EndpointAddress] = set()
        conns = set()

        node = self.system.get_endpoint(endpoint)
        tag = Addresses.get_tag(node.addresses)

        with TextIOWrapper(stream) as f:
            while True:
                line = f.readline()
                if not line:
                    break
                if not columns:
                    # header line, use first two characters (headers are truncated for narrow data)
                    line = line.replace("Local Address:Port", self.LOCAL_ADDRESS)
                    line = line.replace("Peer Address:Port", self.PEER_ADDRESS)
                    columns = {name: idx for idx, name in enumerate(line.split())}
                    assert self.LOCAL_ADDRESS in columns, "Local address not found"
                    assert self.PEER_ADDRESS in columns, "Peer address not found"
                    continue
                cols = line.split()
                if len(cols) <= columns[self.PEER_ADDRESS]:
                    continue  # bad line
                net_id = cols[columns["Netid"]]
                state = cols[columns["State"]]
                local_ip, local_inf, local_port = self._parse_address(cols[columns[self.LOCAL_ADDRESS]])
                peer_ip, _, peer_port = self._parse_address(cols[columns[self.PEER_ADDRESS]])
                self.logger.debug("Local %s:%d Peer %s:%d", local_ip, local_port, peer_ip, peer_port)
                local_add = IPAddress.new(local_ip) if local_ip else None
                peer_add = IPAddress.new(peer_ip) if peer_ip else None
                if local_inf == "lo" or (local_add and local_add.is_loopback()):
                    continue  # loopback is not external
                if not local_add:
                    if not tag:
                        continue  # no host address known, cannot send events
                    local_add = tag
                local_ads.add(local_add)
                if net_id == "udp" and state == "UNCONN":
                    # listening UDP port
                    add = EndpointAddress(local_add or Addresses.ANY, Protocol.UDP, local_port)
                    services.add(add)
                    continue
                if net_id == "tcp" and state == "LISTEN":
                    # listening TCP port
                    add = EndpointAddress(local_add or Addresses.ANY, Protocol.TCP, local_port)
                    services.add(add)
                    continue
                if net_id in {"udp", "tcp"} and state != "LISTEN" and local_add and peer_add:
                    # UDP or TCP connection
                    proto = Protocol.UDP if net_id == "udp" else Protocol.TCP
                    local = EndpointAddress(local_add, proto, local_port)
                    peer = EndpointAddress(peer_add, proto, peer_port)
                    conns.add((local, peer))
                    continue

        if self.send_events:
            evidence = Evidence(source)

            # name events
            adds = sorted(local_ads)
            if tag:
                for a in adds:
                    ev = NameEvent(evidence, service=None, tag=tag, address=a)
                    interface.name(ev)

            # service events
            for addr in sorted(services):
                scan = ServiceScan(evidence, endpoint=AddressEnvelope(tag, addr) if tag else addr)
                interface.service_scan(scan)
            # NOTE: Create host scan event to report missing services

            # connection events
            for conn in sorted(conns):
                s, t = conn
                if s.host in local_ads:
                    # incoming connection
                    t, s = conn
                flow = IPFlow(evidence,
                              source=(HWAddresses.NULL, s.host, s.port),
                              target=(HWAddresses.NULL, t.host, t.port),
                              protocol=s.protocol)
                interface.connection(flow)
                # these are established connections, both ways
                interface.connection(flow.reverse())
