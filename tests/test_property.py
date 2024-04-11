from tcsfw.property import Properties, PropertyKey


def test_property_equality():
    p1 = Properties.EXPECTED
    p2 = PropertyKey("check", "expected")
    assert p1 == p2


def test_property_hashable():
    p1 = Properties.EXPECTED
    p2 = PropertyKey("check", "expected")
    ps = set([p2])
    assert p1 in ps
    assert p2 in ps
    assert PropertyKey("check", "export") not in ps

