"""SPDX SBOM reading tool"""

from io import BytesIO
import json
from datetime import datetime
from typing import cast

from tcsfw.components import Software, SoftwareComponent
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, NodeComponent
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import NodeComponentTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class SPDXReader(NodeComponentTool):
    """Read SPDX component description for a software"""
    def __init__(self, system: IoTSystem):
        super().__init__("spdx", ".json", system)
        self.tool.name = "SPDX SBOM"

    def filter_component(self, component: NodeComponent) -> bool:
        return isinstance(component, Software)

    def process_component(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        software = cast(Software, component)

        evidence = Evidence(source)

        properties = set()

        raw_file = json.load(data_file)

        cr_info = raw_file["creationInfo"]
        source.timestamp = datetime.strptime(cr_info["created"], "%Y-%m-%dT%H:%M:%SZ")

        for index, raw in enumerate(raw_file["packages"]):
            name = raw["name"]
            if index == 0 and name.endswith(".apk"):
                continue  # NOTE A kludge to clean away opened APK itself
            version = raw.get("versionInfo", "")
            if "property 'version'" in version:
                version = ""  # NOTE: Kludging a bug in BlackDuck
            key = PropertyKey("component", name)
            properties.add(key)
            old_sc = software.components.get(name)
            verdict = Verdict.PASS
            if self.load_baseline:
                if old_sc:
                    self.logger.warning("Double definition for component: %s", name)
                    continue
                # component in baseline
                software.components[name] = SoftwareComponent(name, version=version)
            elif not old_sc:
                verdict = Verdict.FAIL  # claim not in baseline
            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(verdict, explanation=f"{name} {version}"))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.COMPONENTS.value_set(properties))
            interface.property_update(ev)
