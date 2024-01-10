from test_inspector import simple_setup_3
from tcsfw.address import IPAddress
from tcsfw.model import Host
from tcsfw.visualizer import Visualizer


def test_model_events():
    sb = simple_setup_3()
    dev1 = sb.device("Device 1").entity
    dev2 = sb.device("Device 2").entity
    dev3 = sb.device("Device 3").entity
    vis = Visualizer()
    vis.placement = [
        "   A",
        " B  ",
        "C   ",
    ]
    vis.handles = {
        "A": dev1,
        "B": dev2,
        "C": dev3,
    }
    x, y = vis.place(dev1)
    assert x == 800 and y == 333
    x, y = vis.place(dev2)
    assert x == 400 and y == 500
    x, y = vis.place(dev3)
    assert x == 200 and y == 667

    x, y = vis.place(Host(sb.system, "New 1"))
    assert x == 333 and y == 167
    x, y = vis.place(Host(sb.system, "New 2"))
    assert x == 667 and y == 167
    x, y = vis.place(Host(sb.system, "New 3"))
    assert x == 200 and y == 167
    x, y = vis.place(Host(sb.system, "New 4"))
    assert x == 400 and y == 167
    x, y = vis.place(Host(sb.system, "New 5"))
    assert x == 600 and y == 167
    x, y = vis.place(Host(sb.system, "New 6"))
    assert x == 800 and y == 167
    x, y = vis.place(Host(sb.system, "New 7"))
    assert x == 111 and y == 167

    re = Host(sb.system, "New 101")
    re.addresses.add(IPAddress.new("5.10.10.10"))
    x, y = vis.place(re)
    assert x == 333 and y == 833
    x, y = vis.place(re)
    assert x == 333 and y == 833
