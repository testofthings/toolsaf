"""Release data reading"""

import datetime
from io import BytesIO
import json
from statistics import mean
from typing import Tuple, List, cast

from tcsfw.components import Software
from tcsfw.event_interface import EventInterface, PropertyEvent
from tcsfw.model import IoTSystem, NetworkNode, NodeComponent
from tcsfw.tools import ComponentCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.release_info import ReleaseInfo


class ReleaseReader(ComponentCheckTool):
    """Read release data aquired from GitLab API"""
    def __init__(self, system: IoTSystem):
        super().__init__("gitlab-releases", ".json", system)
        self.tool.name = "GitLab releases"

    def filter_component(self, component: NetworkNode) -> bool:
        """Filter checked entities"""
        return isinstance(component, Software)

    def process_stream(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        software = cast(Software, component)

        root = json.load(data_file)

        releases: List[Tuple[datetime.datetime, str]] = []
        for rel in root:
            ts = ReleaseInfo.parse_time(rel['published_at'][:10])
            n = rel['tag_name']
            releases.append((ts, n))
        releases = sorted(releases, key=lambda r: r[0], reverse=True)
        d = []
        for i in range(1, len(releases)):
            d.append((releases[i - 1][0] - releases[i][0]).days)

        i = ReleaseInfo(software.name)
        i.latest_release = "No releases", datetime.datetime.fromtimestamp(0)
        i.first_release = i.latest_release
        i.interval_days = 0
        if releases:
            i.latest_release = releases[0][0]
            i.latest_release_name = releases[0][1]
            i.first_release = releases[-1][0]
            i.interval_days = int(mean(d))

        if self.load_baseline:
            software.info = i

        if self.send_events:
            ev = PropertyEvent(Evidence(source), software, (ReleaseInfo.PROPERTY_KEY, i))
            interface.property_update(ev)
