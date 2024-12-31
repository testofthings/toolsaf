"""Tool to read Android manifest XML"""

import json
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree
from typing import Dict, List

from tdsaf.main import ConfigurationException
from tdsaf.common.basics import HostType
from tdsaf.common.address import AnyAddress
from tdsaf.core.components import Software
from tdsaf.core.event_interface import PropertyEvent, EventInterface
from tdsaf.core.model import IoTSystem
from tdsaf.common.property import Properties, PropertyKey
from tdsaf.adapters.tools import EndpointTool
from tdsaf.common.traffic import EvidenceSource, Evidence
from tdsaf.common.verdict import Verdict
from tdsaf.common.android import MobilePermissions


class AndroidManifestScan(EndpointTool):
    """Android manifest XML tool"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("android", ".xml", system)
        self.tool.name = "Android Manifest"
        self.categories = self.load_categories()

    def load_categories(self) -> Dict[str, List[str]]:
        """Load our Android permission category info from json"""
        data_json_path = Path(__file__).parent / "data/android_permissions.json"
        with open(data_json_path, "r", encoding="utf-8") as f:
            return json.load(f) # type: ignore[no-any-return]

    def process_endpoint(self, endpoint: AnyAddress, stream: BytesIO, interface: EventInterface,
                         source: EvidenceSource) -> None:
        node = self.system.get_endpoint(endpoint)
        if node.host_type != HostType.MOBILE:
            raise ConfigurationException(f"Endpoint {endpoint} is not a Mobile application!")

        if len(all_software := Software.list_software(node)) != 1:
            raise ConfigurationException(
                f"Endpoint {endpoint} needs to have 1 SW component only. Current number is {len(all_software)}!")
        software = all_software[0]

        evidence = Evidence(source)

        tree = ElementTree.parse(stream)
        key_set = set()
        for uses_p in tree.getroot().iter('uses-permission'):
            name = str(uses_p.attrib.get("{http://schemas.android.com/apk/res/android}name"))
            if "." in name:
                name = name[name.rindex(".") + 1:]

            category = self.link_permission_to_category(name)
            key = PropertyKey("permission", category.value)
            key_set.add(key)

            if self.load_baseline:
                software.permissions.add(category.value)
                ver = Verdict.PASS
            else:
                ver = Verdict.PASS if category.value in software.permissions else Verdict.FAIL

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(ver))
                interface.property_update(ev)

        # Set verdict for permissions that were only present in the statement
        for permission in software.permissions:
            key = PropertyKey("permission", permission)
            if key not in key_set:
                key_set.add(key)
                ver = Verdict.FAIL if not self.load_baseline else Verdict.PASS
                ev = PropertyEvent(evidence, software, key.verdict(ver))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.PERMISSIONS.value_set(key_set, self.tool.name))
            interface.property_update(ev)

    def link_permission_to_category(self, permission: str) -> MobilePermissions:
        """Connect given permission to one of our categories.
           If no category is found, uncategorized is returned by default."""
        for category, permissions in self.categories.items():
            if permission in permissions:
                return MobilePermissions(category)
        return MobilePermissions.UNCATEGORIZED
