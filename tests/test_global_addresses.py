import pytest

from toolsaf.common.address import GlobalAddress
from toolsaf.main import HTTP, TLS
from tests.test_model import Setup


def test_parse_segment():
    ga = GlobalAddress
    assert ga._parse_segment("Test") == "test"
    assert ga._parse_segment("Test 1") == "test_1"
    assert ga._parse_segment("TCP:443") == "tcp/443"


def test_parse_segments():
    ga = GlobalAddress
    assert ga._parse_segments("Source", "Target", "TCP:443") \
        == ["source", "target", "tcp/443"]
    assert ga._parse_segments(GlobalAddress(["source", "target"]), "TCP:443") \
        == ["source/target", "tcp/443"]
    with pytest.raises(ValueError):
        ga._parse_segments("test", 123)


def test_create_address_value():
    ga = GlobalAddress([""])
    assert ga._create_address_value(["a", "b"]) == "a/b"
    assert ga._create_address_value(["source=test1", "target=test2/abc"]) \
        == "source=test1/target=test2/abc"


def test_global_2():
    a = GlobalAddress.new("a", "b", "c")
    b = GlobalAddress.new(a, "d")
    c = GlobalAddress.new(b, "e")
    d = GlobalAddress.new("00", c, a)

    assert a.get_parseable_value() == "a/b/c"
    assert b.get_parseable_value() == "a/b/c/d"
    assert c.get_parseable_value() == "a/b/c/d/e"
    assert d.get_parseable_value() == "00/a/b/c/d/e/a/b/c"

    with pytest.raises(ValueError):
        GlobalAddress.new(1)


def test_eq():
    assert GlobalAddress(["a", "b"]) == GlobalAddress(["a", "b"])
    assert GlobalAddress(["a", "b"]) == "a/b"
    assert GlobalAddress(["a", "b"]) != GlobalAddress(["a"])
    assert GlobalAddress(["a", "b"]) != "a"
