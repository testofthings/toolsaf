"""PCAP tool"""

from datetime import datetime
from io import BufferedReader
from ipaddress import IPv4Address, IPv6Address
import pathlib
from typing import List, Optional, Dict, Tuple, Any

from framing.backends import RawFrame
from framing.frame_types import dns_frames
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IP_Payloads, IPv4
from framing.frame_types.ipv6_frames import IPReassembler
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, PCAP_Payloads
from framing.frame_types.tcp_frames import TCP, TCPFlag
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw, RawData

from tdsaf.common.address import DNSName, HWAddress, Protocol, IPAddress
from tdsaf.core.event_interface import EventInterface
from tdsaf.core.model import Connection, IoTSystem
from tdsaf.core.services import NameEvent, DNSService
from tdsaf.adapters.tools import SystemWideTool
from tdsaf.common.traffic import IPFlow, EvidenceSource, Evidence, EthernetFlow


class PCAPReader(SystemWideTool):
    """PCAP reading tool"""
    def __init__(self, system: IoTSystem, name: str="PCAP reader") -> None:
        super().__init__("pcap", system)
        self.data_file_suffix = ".pcap"
        if name:
            self.tool.name = name
        # current frame
        self.source: Optional[EvidenceSource] = None
        self.interface: Optional[EventInterface] = None
        self.frame_number = 0
        self.timestamp = datetime.fromtimestamp(0)
        self.ip_reassembler = IPReassembler()
        self.dns_names: Dict[Any, str] = {}  # report one just once

    @classmethod
    def inspect(cls, pcap_file: pathlib.Path, interface: EventInterface) -> 'PCAPReader':
        """Inspect PCAP file and send events to the given interface"""
        r = PCAPReader(interface.get_system())
        with pcap_file.open("rb") as f:
            ev = EvidenceSource(pcap_file.name)
            # tool-specific code can override, if knows better
            ev.timestamp = datetime.fromtimestamp(pcap_file.stat().st_mtime)
            r.process_file(f, pcap_file.name, interface, ev)
        return r

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        self.source = source
        self.interface = interface
        raw_data = Raw.stream(data, request_size=1024 * 1024)
        try:
            self.parse(raw_data)
        finally:
            raw_data.close()
        return True

    def parse(self, raw: RawData) -> int:
        """Parse packets from PCAP data"""
        pcap = PCAPFile(Frames.dissect(raw))
        PCAP_Payloads.add_to(pcap)
        Ethernet_Payloads.add_to(pcap)
        IP_Payloads.add_to(pcap)

        assert self.source, "Source is not set"
        count = 0
        for rec in PCAPFile.Packet_Records.iterate(pcap):
            self.frame_number = count + 1
            try:
                self.timestamp = datetime.fromtimestamp(PacketRecord.Timestamp[rec])
                self.source.timestamp = self.timestamp  # recent
                PacketRecord.Packet_Data.process_frame(rec, {
                    EthernetII: self._ethernet_frame
                })
            except ValueError as e:
                # seen with DNS traffic
                self.logger.warning("Frame %s: %s", self.frame_number, e)
            count += 1
        return count

    def _ethernet_frame(self, frame: EthernetII) -> None:
        """Parse ethernet frame"""
        self.logger.debug("Parse PCAP frame %s", self.frame_number)
        EthernetII.data.process_frame(frame, {
            IPv4: lambda f: self._ipv4_frame(frame, f),
            RawFrame: lambda _: self._other_ethernet_frame(frame),
        })

    def _other_ethernet_frame(self, frame: EthernetII) -> None:
        # we have names for some protocols, use them or use the type number
        pl_type = EthernetII.type[frame]
        protocol = {
            0x0806: Protocol.ARP,
        }.get(pl_type)
        if protocol is None:
            protocol = Protocol.ETHERNET
        else:
            pl_type = -1
        assert self.source, "Source is not set"
        assert self.interface, "Interface is not set"
        ev = Evidence(self.source, f":{self.frame_number}")
        fl = EthernetFlow(ev,
                          source=HWAddress.new(EthernetII.source[frame].as_hw_address()),
                          target=HWAddress.new(EthernetII.destination[frame].as_hw_address()),
                          payload=pl_type,
                          protocol=protocol)
        fl.timestamp = self.timestamp
        self.interface.connection(fl)

        # We used to track packets
        # le = EthernetII.data[frame].byte_length()
        # delta = self.timestamp - fl.timestamp
        # ts = int(delta.total_seconds() * 1000)
        # self.interface.flow_data_update(fl, [ts, le])

    def _ipv4_frame(self, ethernet: EthernetII, frame: IPv4) -> None:
        """Parse IPv4 frame"""
        pl = self.ip_reassembler.push_frame(frame)
        Frames.process(pl, {
            UDP: lambda f: self._udp_frame(ethernet, frame, f),
            TCP: lambda f: self._tcp_frame(ethernet, frame, f),
            RawFrame: lambda f: self._other_ip_frame(ethernet, frame)
        })

    @classmethod
    def ip_flow_ends(cls, ethernet: EthernetII, ip: IPv4, source_port: int, destination_port: int) \
                    -> Tuple[Tuple[Any, Any, Any], Tuple[Any, Any, Any]]:
        """Resolve ends for IP flow object"""
        return (
            HWAddress.new(EthernetII.source[ethernet].as_hw_address()),
            IPAddress(IPv4.Source_IP[ip].as_ip_address()),
            source_port), (
            HWAddress.new(EthernetII.destination[ethernet].as_hw_address()),
            IPAddress(IPv4.Destination_IP[ip].as_ip_address()),
            destination_port
        )

    def _udp_frame(self, ethernet: EthernetII, ip: IPv4, frame: UDP) -> None:
        """Parse UDP frame"""
        assert self.source, "Source is not set"
        assert self.interface, "Interface is not set"

        s, d = self.ip_flow_ends(ethernet, ip, UDP.Source_port[frame], UDP.Destination_port[frame])
        flow = IPFlow(Evidence(self.source, f":{self.frame_number}"), s, d, Protocol.UDP)
        flow.timestamp = self.timestamp
        conn = self.interface.connection(flow)
        proto = self.system.message_listeners.get(conn.target) if conn else None
        if proto:
            proc = {
                Protocol.DNS: lambda: self._dns_message([conn.source, conn.target], frame, conn)
            }[proto]
            proc() # type: ignore [no-untyped-call]

        # We used to track packets
        # le = UDP.Data[frame].byte_length()
        # delta = self.timestamp - flow.timestamp
        # ts = int(delta.total_seconds() * 1000)
        # self.interface.flow_data_update(flow, [ts, le])

    def _dns_message(self, peers: List[IPAddress], udp: UDP, connection: Connection) -> None:
        """Parse DNS message"""
        assert self.source, "Source is not set"
        assert self.interface, "Interface is not set"

        rd = UDP.Data[udp]
        frame = dns_frames.DNSMessage(Frames.dissect(rd))
        evidence = Evidence(self.source, f":{self.frame_number}")
        service = connection.target
        assert isinstance(service, DNSService), f"Unexpected DNS service: {service}"

        events = []
        for rd in dns_frames.DNSMessage.Question.iterate(frame):
            name = dns_frames.DNSName.string(rd, dns_frames.DNSQuestion.QNAME)
            if name not in self.dns_names:
                self.dns_names[name] = ""
                events.append(NameEvent(evidence, service, name=DNSName(name), peers=peers))

        def learn_name(name: str, ip: IPv4Address | IPv6Address) -> None:
            old = self.dns_names.get(ip)
            if old == name:
                return
            self.dns_names[ip] = name
            n = NameEvent(evidence, service, name=DNSName(name), address=IPAddress(ip), peers=peers)
            events.append(n)

        rd_frames = []
        rd_frames.extend(dns_frames.DNSMessage.Answer.iterate(frame))
        rd_frames.extend(dns_frames.DNSMessage.Authority.iterate(frame))
        rd_frames.extend(dns_frames.DNSMessage.Additional.iterate(frame))
        for rd in rd_frames:
            name = dns_frames.DNSName.string(rd, dns_frames.DNSResource.NAME)
            proc_rd = {
                dns_frames.RDATA.A: lambda r:
                    learn_name(name, r.as_ip_address()),  # pylint: disable=cell-var-from-loop
                dns_frames.RDATA.AAAA: lambda r:
                    learn_name(name, r.as_ip_address()),  # pylint: disable=cell-var-from-loop
            }
            dns_frames.DNSResource.RDATA.process_frame(rd, proc_rd)

        for e in events:
            self.interface.name(e)

    def _tcp_frame(self, ethernet: EthernetII, ip: IPv4, frame: TCP) -> None:
        """Parse TCP frame"""
        assert self.source, "Source is not set"
        assert self.interface, "Interface is not set"

        if TCP.Flags[frame] & TCPFlag.SYN:
            # SYN marks connection attempt and accepting it
            s, d = self.ip_flow_ends(ethernet, ip, TCP.Source_port[frame], TCP.Destination_port[frame])
            flow = IPFlow(Evidence(self.source, f":{self.frame_number}"), s, d, Protocol.TCP)
            flow.timestamp = self.timestamp
            self.interface.connection(flow)
        # We used to track packets
        # else:
            # key = self.ip_flow_ends(ethernet, ip, TCP.Source_port[frame], TCP.Destination_port[frame])
            # flow = self.flows.get(key)
            # if flow:
            #     le = TCP.Data[frame].byte_length()
            #     # NOTE: We could make fewer calls and pack more to the list
            #     if le > 0:
            #         delta = self.timestamp - flow.timestamp
            #         ts = int(delta.total_seconds() * 1000)
            #         self.interface.flow_data_update(flow, [ts, le])

    def _other_ip_frame(self, ethernet: EthernetII, ip: IPv4) -> None:
        assert self.source, "Source is not set"
        assert self.interface, "Interface is not set"

        proto = IPv4.Protocol[ip]
        s, d = self.ip_flow_ends(ethernet, ip, proto, proto)
        flow = IPFlow(Evidence(self.source, f":{self.frame_number}"), s, d, Protocol.IP)
        flow.timestamp = self.timestamp
        self.interface.connection(flow)

        # We used to track packets
        # le = IPv4.Payload[ip].byte_length()
        # delta = self.timestamp - flow.timestamp
        # ts = int(delta.total_seconds() * 1000)
        # self.interface.flow_data_update(flow, [ts, le])

    def __repr__(self) -> str:
        return f"{self.source or '???'}:{self.frame_number}"
