"""Tool to read Android manifest XML"""

from io import BytesIO
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


class AndroidManifestScan(EndpointTool):
    """Android manifest XML tool"""
    def __init__(self, system: IoTSystem):
        super().__init__("android", ".xml", system)
        self.tool.name = "Android Manifest"

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

            key = PropertyKey("permission", name)
            val = key.get(software.properties)
            key_set.add(key)

            if self.load_baseline:
                software.permissions.add(name)
                ver = Verdict.PASS
            else:
                ver = Verdict.PASS if val else Verdict.FAIL

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(ver))
                interface.property_update(ev)

        unseen = software.permissions - perm_set
        for name in sorted(unseen):
            # unseen permissions are failures
            if self.send_events:
                key = PropertyKey("permission", name)
                key_set.add(key)
                ev = PropertyEvent(evidence, software, key.verdict(Verdict.FAIL))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.PERMISSIONS.value_set(key_set, self.tool.name))
            interface.property_update(ev)
