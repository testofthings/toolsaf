"""Release data reading"""

import datetime
from io import BytesIO
import json
from statistics import mean
from typing import Tuple, List, cast

from tdsaf.base.components import Software
from tdsaf.base.event_interface import EventInterface, PropertyEvent
from tdsaf.base.model import IoTSystem, NetworkNode, NodeComponent
from tdsaf.adapters.tools import NodeComponentTool
from tdsaf.core.traffic import EvidenceSource, Evidence
from tdsaf.core.release_info import ReleaseInfo


class ReleaseReader(NodeComponentTool):
    """Read release data aquired from GitHub API"""
    def __init__(self, system: IoTSystem):
        super().__init__("github-releases", ".json", system)
        self.tool.name = "GitHub releases"

    def filter_component(self, component: NetworkNode) -> bool:
        """Filter checked entities"""
        return isinstance(component, Software)

    def process_component(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
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
