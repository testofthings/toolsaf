"""SPDX SBOM reading tool"""

from io import BufferedReader
import json
from typing import cast

from toolsaf.main import ConfigurationException
from toolsaf.core.components import Software, SoftwareComponent
from toolsaf.core.event_interface import PropertyEvent, EventInterface
from toolsaf.core.model import IoTSystem, NodeComponent
from toolsaf.adapters.tools import NodeComponentTool
from toolsaf.common.basics import Status
from toolsaf.common.traffic import EvidenceSource, Evidence
from toolsaf.common.verdict import Verdict
from toolsaf.common.property import Properties


class SPDXJson:
    """JSON format SPDX SBOM reader"""
    def __init__(self, file: BufferedReader) -> None:
        self.file = json.load(file)

    def read(self, software: Software) -> list[SoftwareComponent]:
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
                components.append(SoftwareComponent(software, name, version))
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

    def process_component(
        self, component: NodeComponent, data_file: BufferedReader, interface: EventInterface,
        source: EvidenceSource
    ) -> None:
        software = cast(Software, component)
        evidence = Evidence(source)

        found_components = SPDXJson(data_file).read(software)
        found_names = {c.name for c in found_components}

        if self.send_events:
            software.set_seen_now()

        for stated in software.components:
            if stated.name not in found_names and self.send_events:
                interface.property_update(PropertyEvent(
                    evidence, stated,
                    Properties.EXPECTED.verdict(Verdict.FAIL, explanation="Component not found in SBOM")
                ))

        for found in found_components:
            existing = software.get_component(found.name)
            if existing and self.send_events:
                interface.property_update(PropertyEvent(
                    evidence, existing, Properties.EXPECTED.verdict(Verdict.PASS)
                ))

            else:
                if not self.load_baseline:
                    found.status = Status.UNEXPECTED
                software.components.append(found)

                if self.send_events:
                    found.set_seen_now()
                    interface.property_update(PropertyEvent(
                        evidence, found,
                        Properties.EXPECTED.verdict(Verdict.FAIL, explanation="Component in SBOM but not declared")
                    ))
