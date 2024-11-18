"""Tool to read Android manifest XML"""

import json
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

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
    def __init__(self, system: IoTSystem):
        super().__init__("android", ".xml", system)
        self.tool.name = "Android Manifest"
        self.categories = self.load_categories()

    def load_categories(self) -> dict:
        """Load our Android permission category info from json"""
        data_json_path = Path(__file__).parent / "data/android_permissions.json"
        with open(data_json_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def process_endpoint(self, endpoint: AnyAddress, stream: BytesIO, interface: EventInterface,
                         source: EvidenceSource):
        node = self.system.get_endpoint(endpoint)
        if node.host_type != HostType.MOBILE:
            raise ConfigurationException(f"Endpoint {endpoint} is not a Mobile application!")

        software = Software.list_software(node)
        if len(software) != 1:
            raise ConfigurationException(
                f"Endpoint {endpoint} needs to have 1 SW component only. Current number is {len(software)}!")
        software = software[0]

        evidence = Evidence(source)

        tree = ElementTree.parse(stream)
        perm_set = set()
        key_set = set()
        for uses_p in tree.getroot().iter('uses-permission'):
            name = uses_p.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if "." in name:
                name = name[name.rindex(".") + 1:]
            perm_set.add(name)

            category = self.link_permission_to_category(name)
            key = PropertyKey("permission", category.value)
            key_set.add(key)

            if self.load_baseline:
                software.permissions.add(name)
                ver = Verdict.PASS
            else:
                ver = Verdict.PASS if category.value in software.permissions else Verdict.FAIL

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(ver))
                interface.property_update(ev)

        # FIXME: What if a permission is set in DSL, but its not present in the manifest?
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
