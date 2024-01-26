from datetime import datetime
from io import BytesIO, TextIOWrapper
import re
from typing import Tuple, List

import requests
import urllib

from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, NetworkNode
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import BaseFileCheckTool, NodeCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class WebChecker(BaseFileCheckTool):
    """Check web pages"""
    def __init__(self, system: IoTSystem):
        super().__init__("web", system)  # no extension really
        self.data_file_suffix = ".http"
        self.tool.name = "Web check"
        self.regexp = re.compile(r'^HTTP\/.*? (\d\d\d)(.*)$')

    def process_file(self, data: BytesIO, file_name: str, interface: EventInterface, source: EvidenceSource) -> bool:
        if file_name.endswith(self.data_file_suffix):
            file_name = file_name[:-len(self.data_file_suffix)]
        f_url = urllib.parse.unquote(file_name)

        with TextIOWrapper(data) as f:
            stat_line = self.regexp.match(f.readline())
            status_code = int(stat_line.group(1))
            status_text = f"{status_code}{stat_line.group(2).strip()}"
            ok = status_code == 200

        for key, url in self.system.online_resources.items():
            if f_url != url:
                continue
            self.logger.info("web link %s: %s", url, status_text)
            kv = Properties.DOCUMENT_AVAILABILITY.append_key(key).value(Verdict.PASS if ok else Verdict.FAIL, status_text)
            source.timestamp = datetime.now()  # FIXME: get timestamp from the file
            evidence = Evidence(source, url)
            ev = PropertyEvent(evidence, self.system, kv)
            interface.property_update(ev)
            break
        else:
            self.logger.warning("file without matching resource %s", f_url)

        return True