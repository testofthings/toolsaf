"""HAR JSON tool"""

from io import BytesIO
import json
import urllib.parse
from datetime import datetime
from typing import cast

from tcsfw.address import EndpointAddress, DNSName, Protocol
from tcsfw.components import Cookies, CookieData
from tcsfw.event_interface import PropertyAddressEvent, PropertyEvent, EventInterface
from tcsfw.model import Host, IoTSystem, NetworkNode
from tcsfw.property import PropertyKey, Properties
from tcsfw.tools import NodeCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class HARScan(NodeCheckTool):
    """HAR JSON tool"""
    def __init__(self, system: IoTSystem):
        super().__init__("har", ".json", system)
        self.tool.name = "HAR"

    def filter_component(self, node: NetworkNode) -> bool:
        return isinstance(node, Host)

    def process_stream(self, node: NetworkNode, data_file: BytesIO, interface: EventInterface, source: EvidenceSource):
        host = cast(Host, node)

        component = Cookies.cookies_for(host)
        evidence = Evidence(source)

        unseen = set(component.cookies.keys())  # cookies not seen in HAR
        wildcards = {}  # cookie wildcards
        for n, c in component.cookies.items():
            if "*" in n:
                pf = n[:n.rindex("*")]
                wildcards[pf] = c
                unseen.discard(n)

        def decode(s: str) -> str:
            return urllib.parse.unquote(s)

        properties = set()

        raw_log = json.load(data_file)["log"]

        raw_entries = raw_log["entries"]
        for raw in raw_entries:
            source.timestamp = datetime.strptime(raw["startedDateTime"], "%Y-%m-%dT%H:%M:%S.%fZ")

            request = raw["request"]
            req_url = request["url"]
            for raw_c in request.get("cookies"):
                name = decode(raw_c["name"])
                p_key = PropertyKey("cookie", name)
                properties.add(p_key)
                for w, cookie in wildcards.items():
                    if name.startswith(w):
                        break
                else:
                    cookie = component.cookies.get(name)
                n_cookie = CookieData(decode(raw_c.get("domain", "")), decode(raw_c.get("path", "/")))
                verdict = Verdict.PASS
                if self.load_baseline:
                    # loading baseline values
                    if cookie is not None:
                        self.logger.warning("Double definition for cookie: %s", name)
                        # raise Exception("Double definition for cookie: " + name)
                    component.cookies[name] = n_cookie
                    unseen.discard(name)
                elif cookie:
                    # old exists, verify match
                    unseen.discard(name)
                    if cookie.path != n_cookie.path or cookie.domain != n_cookie.domain:
                        verdict = Verdict.FAIL
                else:
                    verdict = Verdict.FAIL  # unexpected, not in baseline
                if self.send_events:
                    ev = PropertyEvent(evidence, component, p_key.verdict(verdict))
                    interface.property_update(ev)
            response = raw["response"]
            red_url = response.get("redirectURL", "")
            if red_url.startswith("https:") and req_url.startswith("http:"):
                # redirection to HTTPS, someone may be interested
                ru = urllib.parse.urlparse(req_url)
                ep = EndpointAddress(DNSName.name_or_ip(str(ru.hostname)), Protocol.TCP, ru.port or 80)
                txt = f"{response.get('status', '?')} {response.get('statusText', '?')}"
                ev = PropertyAddressEvent(evidence, ep, Properties.HTTP_REDIRECT.verdict(Verdict.PASS, txt))
                interface.property_address_update(ev)

        for n, cookie in component.cookies.items():
            if n in unseen:
                # cookie not seen in HAR
                p_key = PropertyKey("cookie", n)
                properties.add(p_key)
                if self.send_events:
                    ev = PropertyEvent(evidence, component, p_key.verdict(Verdict.FAIL, "Not seen in HAR"))
                    interface.property_update(ev)

        # cookie scan event
        if self.send_events:
            ev = PropertyEvent(evidence, component, Properties.COOKIES.value_set(properties))
            interface.property_update(ev)
