import json
import pathlib
import tempfile

from tcsfw.builder_backend import SystemBackend
from tcsfw.client_api import APIRequest, ClientAPI
from tcsfw.inspector import Inspector
from tcsfw.matcher import SystemMatcher
from tcsfw.registry import Registry
from tcsfw.verdict import Verdict


def test_ping_upload():
    # create a temporary directory
    sb = SystemBackend()
    dev = sb.device().ip("192.168.68.1")
    m = Registry(Inspector(sb.system))
    api = ClientAPI(m)
    assert dev.entity.get_expected_verdict() == Verdict.INCON

    with tempfile.TemporaryDirectory() as temp_dir:
        path = pathlib.Path(temp_dir)
        # create a meta file
        meta_file = path / "00meta.json"
        with meta_file.open("w") as f:
            f.write(json.dumps({"file_type": "ping"}))
        file = path / "ping.log"
        with file.open("w") as f:
            f.write(
                """\n"""
                """PING 192.168.68.1 (192.168.68.1) 56(84) bytes of data.\n"""
                """64 bytes from 192.168.68.1: icmp_seq=1 ttl=64 time=4.81 ms\n"""
                """--- 192.168.68.1 ping statistics ---\n"""
                """\n"""
                """1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"""
                """rtt min/avg/max/mdev = 4.810/4.810/4.810/0.000 ms\n"""
            )
        req = APIRequest("batch")
        r = api.api_post_file(req, path)

    assert not r
    assert dev.entity.get_expected_verdict() == Verdict.PASS
