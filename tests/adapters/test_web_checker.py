import pytest
from io import BytesIO, BufferedReader, TextIOWrapper
from typing import Union, List

from toolsaf.adapters.web_checker import WebChecker
from toolsaf.core.online_resources import OnlineResource
from toolsaf.builder_backend import SystemBackend
from toolsaf.common.property import Properties
from toolsaf.common.traffic import EvidenceSource
from toolsaf.common.verdict import Verdict
from toolsaf.main import ConfigurationException
from tests.test_model import Setup


def _data(data: str) -> TextIOWrapper:
    io_data = BytesIO()
    io_data.write(data.encode("utf-8"))
    io_data.seek(0)
    return TextIOWrapper(BufferedReader(io_data))


def _bytesio_data(data: str) -> BytesIO:
    io_data = BytesIO()
    io_data.write(data.encode("utf-8"))
    io_data.seek(0)
    return io_data


def _add_online_resources(system: SystemBackend, resource: List):
    name, url, keywords = resource
    system.online_resource(name, url, keywords)


def test_add_online_resource_to_system():
    system = Setup().system
    system.online_resource("test-policy", "test.com", keywords=[
        "test1", "test2"
    ])
    res = system.system.online_resources[0]
    assert res.name == "test-policy"
    assert res.url == "test.com"
    assert res.keywords == ["test1", "test2"]


def test_add_online_resource_with_zero_keywords():
    with pytest.raises(ConfigurationException):
        Setup().system.online_resource("test-policy", "test.com", keywords=[])


@pytest.mark.parametrize(
    "data, raises, exp",
    [
        (_data("test"), True, None),
        (_data("http://test.com/test"), False, "http://test.com/test")
    ]
)
def test_get_url_from_data(data: TextIOWrapper, raises: bool, exp: Union[str, None]):
    w = WebChecker(Setup().get_system())
    if raises:
        with pytest.raises(ValueError):
            w.get_url_from_data(data)
    else:
        assert w.get_url_from_data(data) == exp


@pytest.mark.parametrize(
    "res, url, exp",
    [
        (("test-policy", "test.com", ["kw1", "kw2"]), "none", None),
        (("test-policy", "test.com", ["kw1", "kw2"]), "test.com", "test-policy"),
    ]
)
def test_get_online_resource_for_url(res: List, url: str, exp: str):
    system = Setup().system
    _add_online_resources(system, res)
    if exp is None:
        assert WebChecker(system.system).get_online_resource_for_url(url) is None
    else:
        assert WebChecker(system.system).get_online_resource_for_url(url).name == res[0]


@pytest.mark.parametrize(
    "data, raises, exp",
    [
        (_data("test"), True, None),
        (_data("HTTP/2 aaa"), True, None),
        (_data("HTTP/2 200"), False, 200),
    ]
)
def test_get_status_code_from_data(data: TextIOWrapper, raises: bool, exp: Union[int, None]):
    w = WebChecker(Setup().get_system())
    if raises:
        with pytest.raises(ValueError):
            w.get_status_code_from_data(data)
    else:
        assert w.get_status_code_from_data(data) == exp


@pytest.mark.parametrize(
    "data, resource, exp",
    {
        (
            _data("privacy policy personal data\nterms."),
            OnlineResource("", "", keywords=["test1", "test2"]),
            False
        ),
        (
            _data("Our privacy policy is very good,\ncome to terms with it."),
            OnlineResource("", "", keywords=["privacy policy", "terms"]),
            True
        ),
    }
)
def test_check_keywords(data: TextIOWrapper, resource: OnlineResource, exp: bool):
    assert WebChecker(Setup().get_system()).check_keywords(resource, data) == exp



@pytest.mark.parametrize(
    "keywords, exp",
    [
        (["privacy policy", "statement"], Verdict.PASS),
        (["HTTP"], Verdict.FAIL)
    ]
)
def test_process_file(keywords: List[str], exp: Verdict):
    setup = Setup()
    data = _bytesio_data(
        "http://test.com\n" +
        "HTTP/2 200\n" +
        "privacy policy\n" +
        "statement"
    )
    setup.system.online_resource("test", "http://test.com", keywords)

    WebChecker(setup.get_system()).process_file(
        data, "", setup.get_inspector(), EvidenceSource("")
    )

    prop = setup.get_system().properties
    assert len(prop) == 1
    assert prop.get(Properties.DOCUMENT_AVAILABILITY.append_key("test")).verdict == exp

