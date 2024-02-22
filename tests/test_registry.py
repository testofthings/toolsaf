from test_inspector import simple_setup_3
from test_model import simple_setup_1
from tcsfw.inspector import Inspector
from tcsfw.main import SystemBuilder, DHCP
from tcsfw.registry import Registry
from tcsfw.traffic import IPFlow, NO_EVIDENCE
from tcsfw.verdict import Status, Verdict


def test_reset():
    sb = simple_setup_3()
    s = sb.system
    r = Registry(Inspector(s))
    dev1 = sb.device("Device 1").entity
    dev2 = sb.device("Device 2").entity
    dev3 = sb.device("Device 3").entity

    assert len(s.children) == 3
    assert len(dev1.connections) == 1

    cache = {}
    assert dev1.get_verdict(cache) == Verdict.INCON

    # expected connections
    cs1 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs2 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    # connection from unexpected host
    cs3 = r.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    # connection to unexpected host
    cs4 = r.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1100) << ("1:0:0:0:0:1", "192.168.0.1", 1234))
    # unexpected service in known host
    cs5 = r.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))

    cache = {}
    assert dev1.get_verdict(cache) == Verdict.FAIL

    # unknown hosts / connections added
    assert len(s.children) == 4
    assert s.children[3].status == Status.UNEXPECTED
    assert len(dev1.connections) == 2
    assert dev1.connections[1].status == Status.UNEXPECTED

    # disable all sources
    r.reset().do_all_tasks()

    cache = {}
    assert dev1.get_verdict(cache) == Verdict.INCON

    # unknown hosts / connections remains as UNDEFINED
    assert len(s.children) == 4
    assert s.children[3].status == Status.PLACEHOLDER
    assert len(dev1.connections) == 2
    assert dev1.connections[1].status == Status.PLACEHOLDER

    # enable sources again
    r.reset(enable_all=True).do_all_tasks()

    cache = {}
    assert dev1.get_verdict(cache) == Verdict.FAIL

    assert len(s.children) == 4
    assert s.children[3].status == Status.UNEXPECTED
    assert len(dev1.connections) == 2
    assert dev1.connections[1].status == Status.UNEXPECTED


def test_reset_2():
    sb = simple_setup_1(external=True)
    r = Registry(Inspector(sb.system))

    flows = r.logging.collect_flows()
    assert len(flows) == 1

    c1 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert c1.status == Status.EXPECTED
    assert c1.is_relevant(ignore_ends=True)
    c2 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:3", "1.0.0.3", 1234))
    assert c2.status == Status.UNEXPECTED
    assert c2.is_relevant(ignore_ends=True)
    c3 = r.connection(IPFlow.UDP("1:0:0:1:0:4", "192.168.0.3", 1100) >> ("1:0:0:0:0:4", "1.0.0.4", 1234))
    assert c3.status == Status.EXTERNAL
    assert not c3.is_relevant(ignore_ends=True)
    flows = r.logging.collect_flows()
    assert len(flows) == 3

    r.reset().do_all_tasks()
    assert c1.status == Status.EXPECTED
    assert c1.is_relevant(ignore_ends=True)
    assert c2.status == Status.PLACEHOLDER
    assert not c2.is_relevant(ignore_ends=True)
    assert c3.status == Status.PLACEHOLDER
    assert not c3.is_relevant(ignore_ends=True)
    flows = r.logging.collect_flows()
    assert len(flows) == 1

    r.reset(enable_all=True).do_all_tasks()
    assert c1.status == Status.EXPECTED
    assert c1.is_relevant(ignore_ends=True)
    assert c2.status == Status.UNEXPECTED
    assert c2.is_relevant(ignore_ends=True)
    assert c3.status == Status.EXTERNAL
    assert not c3.is_relevant(ignore_ends=True)
    flows = r.logging.collect_flows()
    assert len(flows) == 3


def test_reset_dhcp():
    sb = SystemBuilder()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dhcp = sb.any() / DHCP
    c1 = dev1 >> dhcp
    r = Registry(Inspector(sb.system))

    f1 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "0.0.0.0", 68) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 67))
    f2 = r.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 68) << ("1:0:0:0:0:2", "192.168.0.2", 67))

    cli = dev1.entity
    ser = dhcp.entity

    assert len(cli.children) == 1
    assert len(cli.connections) == 1
    assert cli.children[0].status == Status.EXPECTED
    assert cli.children[0].get_expected_verdict() == Verdict.PASS

    # disable all sources
    r.reset().do_all_tasks()

    assert len(cli.children) == 1
    assert len(cli.connections) == 1
    assert cli.children[0].status == Status.EXPECTED
    assert cli.children[0].get_expected_verdict() == Verdict.INCON

    # enable sources again
    r.reset(enable_all=True).do_all_tasks()

    assert len(cli.children) == 1
    assert len(cli.connections) == 1
    assert cli.children[0].status == Status.EXPECTED
    assert cli.children[0].get_expected_verdict() == Verdict.PASS
