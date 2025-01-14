"""Check precense of saved web pages"""

import re
from typing import Union
from urllib import parse
from io import BufferedReader, TextIOWrapper

from tdsaf.core.event_interface import PropertyEvent, EventInterface
from tdsaf.core.model import IoTSystem
from tdsaf.common.property import Properties
from tdsaf.adapters.tools import SystemWideTool
from tdsaf.common.traffic import EvidenceSource, Evidence
from tdsaf.common.verdict import Verdict
from tdsaf.core.online_resources import OnlineResource

class WebChecker(SystemWideTool):
    """Check web pages tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("web", system)  # no extension really
        self.data_file_suffix = ".http"
        self.tool.name = "Web check"
        self.regexp = re.compile(r'^HTTP\/.*? (\d\d\d)(.*)$')

    def get_url_from_data(self, data: TextIOWrapper) -> str:
        """Check the start of given data for a valid URL.
           Raises ValueError if no proper URL found at start of the file"""
        url = data.readline().strip()
        res = parse.urlparse(url)
        if not all([res.scheme, res.netloc]):
            raise ValueError("File does not start with a proper URL")
        return url

    def get_online_resource_for_url(self, url: str) -> Union[OnlineResource, None]:
        """Get online resource that matches given URL"""
        for resource in self.system.online_resources:
            if url == resource.url:
                return resource
        return None

    def get_status_code_from_data(self, data: TextIOWrapper) -> int:
        """Extracts HTTP status code from data. It should be on line 2"""
        try:
            m = self.regexp.match(data.readline())
            if m is None:
                raise ValueError("Proper status code not found on line two")
            return int(m.group(1))
        except (ValueError) as e:
            raise ValueError("Proper status code not found on line two") from e

    def check_keywords(self, resource: OnlineResource, data: TextIOWrapper) -> bool:
        """Check that given keywords found on the page"""
        keywords: set[str] = set(resource.keywords)
        for line in data:
            line = line.strip().lower()
            found_keywords = {kw for kw in keywords if kw in line}
            keywords -= found_keywords
            if not keywords:
                return True
        return not bool(keywords)

    def process_file(self, data: BufferedReader, file_name: str,
                     interface: EventInterface, source: EvidenceSource) -> bool:
        with TextIOWrapper(data) as f:
            url = self.get_url_from_data(f)
            if (resource := self.get_online_resource_for_url(url)) is None:
                self.logger.warning("file without matching resource %s", file_name)
                return True

            status_code = self.get_status_code_from_data(f)
            self.logger.info("web link %s: %s", url, status_code)

            keywords_ok = self.check_keywords(resource, f)
            is_ok = status_code == 200 and keywords_ok
            kv = Properties.DOCUMENT_AVAILABILITY.append_key(resource.name).verdict(
                Verdict.PASS if is_ok else Verdict.FAIL
            )

            evidence = Evidence(source, url)
            ev = PropertyEvent(evidence, self.system, kv)
            interface.property_update(ev)

        return True
