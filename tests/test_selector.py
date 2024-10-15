from tcsfw.basics import HostType
from test_model import simple_setup_1
from tcsfw.model import IoTSystem, Host
from tcsfw.requirement import SelectorContext
from tcsfw.selector import Select


def test_iterate():
    r = list(IoTSystem().iterate())
    assert len(r) == 1

    sb = simple_setup_1()
    r = list(sb.system.iterate())
    assert r[0].long_name() == "Unnamed system"
    assert r[1].long_name() == "Device 1"
    assert r[2].long_name() == "Device 2"
    assert r[3].long_name() == "Device 2 UDP:1234"
    assert r[4].long_name() == "Device 3"
    assert r[5].long_name() == "Device 1 => Device 2 UDP:1234"
    assert r[6] == r[5]  # NOTE: Should we filter?
    assert len(r) == 7


def test_select():
    sb = simple_setup_1()
    ctx = SelectorContext()
    h = list(Select.host().select(sb.system, ctx))
    assert len(h) == 3

    h = list(Select.host().type_of(HostType.MOBILE).select(sb.system, ctx))
    assert len(h) == 0

    h = list(Select.host().type_of(HostType.DEVICE).select(sb.system, ctx))
    assert len(h) == 3

    r = list(Select.host().select(h[0], ctx))
    assert len(r) == 1

    s = list(Select.service().select(h[0], ctx))
    assert len(s) == 0
    s = list(Select.service().select(h[2], ctx))
    assert len(s) == 0
    s = list(Select.service().select(h[1], ctx))
    assert len(s) == 1

    c = list(Select.connection().select(sb.system, ctx))
    assert len(c) == 1

    c = list((Select.service() + Select.host()).select(h[1], ctx))
    assert len(c) == 2


def test_select_data():
    sb = simple_setup_1()
    ctx = SelectorContext()
    h = list(Select.data().select(sb.system, ctx))
    assert len(h) == 0

    data = sb.data(["A data", "B data"], personal=True)
    data.used_by(hosts=[sb.device("Device 1")])

    h = list(Select.data().select(sb.system, ctx))
    assert len(h) == 2

    h = list(Select.data().parameters().select(sb.system, ctx))
    assert len(h) == 0

    h = list(Select.data().personal().select(sb.system, ctx))
    assert len(h) == 2
