"""Check precense of saved web pages"""

import re
from typing import Union
from urllib import parse
from io import BytesIO, TextIOWrapper

from tdsaf.core.event_interface import PropertyEvent, EventInterface
from tdsaf.core.model import IoTSystem
from tdsaf.common.property import Properties
from tdsaf.adapters.tools import SystemWideTool
from tdsaf.common.traffic import EvidenceSource, Evidence
from tdsaf.common.verdict import Verdict


class WebChecker(SystemWideTool):
    """Check web pages tool"""
    def __init__(self, system: IoTSystem):
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

    def get_online_resource_for_url(self, url: str) -> Union[str, None]:
        """Get online resource that matches given URL"""
        for k, v in self.system.online_resources.items():
            if v == url:
                return k
        return None

    def get_status_code_from_data(self, data: TextIOWrapper) -> int:
        """Extracts HTTP status code from data. It should be on line 2"""
        try:
            return int(self.regexp.match(data.readline()).group(1))
        except (AttributeError, ValueError) as e:
            raise ValueError("Proper status code not found on line two") from e

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        with TextIOWrapper(data) as f:
            url = self.get_url_from_data(f)
            if (resource := self.get_online_resource_for_url(url)) is None:
                self.logger.warning("file without matching resource %s", file_name)
                return True

            status_code = self.get_status_code_from_data(f)
            self.logger.info("web link %s: %s", url, status_code)

            is_ok = status_code == 200
            kv = Properties.DOCUMENT_AVAILABILITY.append_key(resource).verdict(
                Verdict.PASS if is_ok else Verdict.FAIL
            )

            # Keyword check, and a related enum for different online resource types?

            evidence = Evidence(source, url)
            ev = PropertyEvent(evidence, self.system, kv)
            interface.property_update(ev)

        return True
