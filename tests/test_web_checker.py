import pytest
from io import BytesIO, BufferedReader, TextIOWrapper
from typing import Union

from tdsaf.adapters.web_checker import WebChecker#, Keywords
from tdsaf.common.online_resources import *
from tdsaf.builder_backend import SystemBackend
from tests.test_model import Setup


def _data(data: str) -> TextIOWrapper:
    io_data = BytesIO()
    io_data.write(data.encode("utf-8"))
    io_data.seek(0)
    return TextIOWrapper(BufferedReader(io_data))


def _add_online_resources(system: SystemBackend, o_res: dict):
    for k, v in o_res.items():
        system.online_resource(k, url=v)


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
    "o_res, url, exp",
    [
        ({"privacy-policy": "test"}, "none", None),
        ({"privacy-policy": "test"}, "test", "privacy-policy"),
    ]
)
def test_get_online_resource_for_url(o_res: dict, url: str, exp: str):
    system = Setup().system
    _add_online_resources(system, o_res)
    assert WebChecker(system.system).get_online_resource_for_url(url) == exp


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
        (_data("privacy policy personal data\nterms"), PrivacyPolicy, False),
        (
            _data("privacy policy personal data\nterms consent third party"),
            PrivacyPolicy, True
        ),
        (
            _data("vulnerability disclosure policy report a bug now submit" +
                  " to our security scope"),
            SecurityPolicy, True
        ),
        (
            _data("our cookie policy is stored, deleted and blocked on expiry\n\
                  for functional marketing purposes statistically"),
            CookiePolicy, True
        ),
    }
)
def test_check_keywords(data: TextIOWrapper, resource: OnlineResource, exp: bool):
    assert WebChecker(Setup().get_system()).check_keywords(resource, data) == exp
