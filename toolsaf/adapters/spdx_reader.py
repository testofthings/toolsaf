"""SPDX SBOM reading tool"""

from io import BufferedReader
import json
from typing import cast

from toolsaf.main import ConfigurationException
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.event_interface import PropertyEvent, EventInterface
from toolsaf.core.model import IoTSystem, NodeComponent
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.adapters.tools import NodeComponentTool
from toolsaf.common.traffic import EvidenceSource, Evidence
from toolsaf.common.verdict import Verdict


class SPDXJson:
    """JSON format SPDX SBOM reader"""
    def __init__(self, file: BufferedReader) -> None:
        self.file = json.load(file)

    def read(self) -> list[SoftwareComponent]:
        """Read list of SoftwareComponents"""
        components = []
        try:
            for i, package in enumerate(self.file["packages"]):
                name = package["name"]
                version = package.get("versionInfo", "")
                if i == 0 and name.endswith(".apk"):
                    continue # NOTE A kludge to clean away opened APK itself
                if "property 'version'" in version:
                    version = ""  # NOTE: Kludging a bug in BlackDuck
                components.append(SoftwareComponent(name, version))
            return components
        except KeyError as e:
            raise ConfigurationException(f"Field {e} missing from SPDX JSON") from e


class SPDXReader(NodeComponentTool):
    """Read SPDX component description for a software"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("spdx", ".json", system)
        self.tool.name = "SPDX SBOM"

    def filter_component(self, component: NodeComponent) -> bool:
        return isinstance(component, Software)

    def process_component(self, component: NodeComponent, data_file: BufferedReader, interface: EventInterface,
                       source: EvidenceSource) -> None:
        software = cast(Software, component)
        evidence = Evidence(source)
        properties = set()

        components = SPDXJson(data_file).read()
        for c in software.components.values():
            if c not in components and self.send_events:
                key = PropertyKey("component", c.name)
                ev = PropertyEvent(evidence, software, key.verdict(Verdict.FAIL, explanation=f"{c.name} {c.version}"))
                interface.property_update(ev)

        for c in components:
            key = PropertyKey("component", c.name)
            properties.add(key)
            old_sc = software.components.get(c.name)
            verdict = Verdict.PASS

            if self.load_baseline:
                software.components[c.name] = c

            if not old_sc and not self.load_baseline:
                verdict = Verdict.FAIL
                software.components[c.name] = c

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(verdict, explanation=f"{c.name} {c.version}"))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.COMPONENTS.value_set(properties))
            interface.property_update(ev)
