"""Release data reading"""

import datetime
from io import BytesIO
import json
from statistics import mean
from typing import Tuple, List, cast

from tdsaf.core.components import Software
from tdsaf.core.event_interface import EventInterface, PropertyEvent
from tdsaf.core.model import IoTSystem, NetworkNode, NodeComponent
from tdsaf.adapters.tools import NodeComponentTool
from tdsaf.common.traffic import EvidenceSource, Evidence
from tdsaf.common.release_info import ReleaseInfo


class ReleaseReader(NodeComponentTool):
    """Read release data aquired from GitHub API"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("github-releases", ".json", system)
        self.tool.name = "GitHub releases"

    def filter_component(self, component: NetworkNode) -> bool:
        """Filter checked entities"""
        return isinstance(component, Software)

    def process_component(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource) -> None:
        software = cast(Software, component)

        root = json.load(data_file)

        releases: List[Tuple[datetime.datetime, str]] = []
        for rel in root:
            ts = cast(datetime.datetime, ReleaseInfo.parse_time(rel['published_at'][:10]))
            n = rel['tag_name']
            releases.append((ts, n))
        releases = sorted(releases, key=lambda r: r[0], reverse=True)
        d = []
        for idx in range(1, len(releases)):
            d.append((releases[idx - 1][0] - releases[idx][0]).days)

        info = ReleaseInfo(software.name)
        info.latest_release = "No releases", datetime.datetime.fromtimestamp(0) # type: ignore[assignment]
        info.first_release = info.latest_release
        info.interval_days = 0
        if releases:
            info.latest_release = releases[0][0]
            info.latest_release_name = releases[0][1]
            info.first_release = releases[-1][0]
            info.interval_days = int(mean(d))

        if self.load_baseline:
            software.info = info

        if self.send_events:
            ev = PropertyEvent(Evidence(source), software, (ReleaseInfo.PROPERTY_KEY, info))
            interface.property_update(ev)
