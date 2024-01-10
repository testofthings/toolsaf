import pathlib

from tcsfw.matcher import SystemMatcher
from tcsfw.pcap_reader import PCAPReader
from tcsfw.traffic import IPFlow


def test_pcap():
    pcap = PCAPReader.inspect(pathlib.Path("tests/samples/deltaco-setup.pcap"))
    m = SystemMatcher(pcap.system)
    cs = m.system.collect_flows()

    c = m.connection(IPFlow.tcp_flow(source_hw="7c:f6:66:24:a7:36", target_ip="18.195.249.137", target_port=443))
    c_flows = cs[c]
    assert len(c_flows) == 12

    c = m.connection(IPFlow.udp_flow(source_hw="86:df:86:76:53:bd", target_hw="dc:a6:32:28:34:e3", target_port=53))
    c_flows = cs[c]
    assert len(c_flows) == 2
